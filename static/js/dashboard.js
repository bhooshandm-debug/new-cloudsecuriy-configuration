(function () {
  "use strict";

  // Confirm destructive actions (CSP forbids inline handlers, so this lives here).
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  // Account form: show only the selected provider's fields.
  var select = document.getElementById("provider");
  if (select) {
    var apply = function () {
      document.querySelectorAll(".prov-fields").forEach(function (box) {
        var on = box.dataset.provider === select.value;
        box.hidden = !on;
        box.querySelectorAll("input, textarea").forEach(function (el) { el.disabled = !on; });
      });
    };
    select.addEventListener("change", apply);
    apply();
  }

  // Dashboard: update the overview quietly in the background.
  var bar = document.getElementById("severity-bars");
  if (bar) {
    var refreshButton = document.getElementById("refresh-dashboard");
    var refreshing = false;
    var applyStats = function (data) {
      document.getElementById("stat-accounts").textContent = data.accounts;
      document.getElementById("stat-scanned").textContent = data.scanned_accounts;
      document.getElementById("stat-failed").textContent = data.failed_total;
      document.getElementById("severity-total").textContent = data.failed_total;
      Object.keys(data.severities).forEach(function (severity) {
        var count = data.severities[severity];
        var segment = bar.querySelector('[data-sev="' + severity + '"]');
        if (segment) {
          segment.dataset.value = count;
          segment.style.flexGrow = count;
          segment.title = severity.charAt(0).toUpperCase() + severity.slice(1) + ": " + count + " failed checks";
          segment.setAttribute("aria-label", segment.title);
        }
        var legendCount = document.querySelector('[data-count="' + severity + '"]');
        if (legendCount) legendCount.textContent = count;
      });
      Object.keys(data.providers || {}).forEach(function (provider) {
        var values = data.providers[provider];
        ["accounts", "scanned_accounts", "failed_total"].forEach(function (key) {
          var el = document.querySelector('[data-provider-' + (key === "accounts" ? "accounts" : key === "scanned_accounts" ? "scanned" : "failed") + '="' + provider + '"]');
          if (el) el.textContent = values[key];
        });
      });
    };
    bar.querySelectorAll(".seg").forEach(function (segment) {
      segment.style.flexGrow = segment.dataset.value;
    });
    var refresh = function () {
      if (refreshing) return;
      refreshing = true;
      if (refreshButton) refreshButton.disabled = true;
      fetch("/dashboard/stats", { credentials: "same-origin" })
        .then(function (response) {
          if (!response.ok) throw new Error("Dashboard refresh failed");
          return response.json();
        })
        .then(function (data) {
          applyStats(data);
        })
        .catch(function () {})
        .then(function () { refreshing = false; if (refreshButton) refreshButton.disabled = false; });
    };
    if (refreshButton) refreshButton.addEventListener("click", refresh);
    setInterval(refresh, 30000);
  }

  var scanFilter = document.getElementById("scan-provider-filter");
  if (scanFilter) {
    scanFilter.addEventListener("change", function () {
      document.querySelectorAll(".dashboard-table tbody tr[data-scan-provider]").forEach(function (row) {
        row.hidden = scanFilter.value !== "all" && row.dataset.scanProvider !== scanFilter.value;
      });
    });
  }

  // AI assistant: render safe Markdown-style text without executing provider HTML.
  var assistantForm = document.getElementById("assistant-form");
  var assistantPanel = document.getElementById("assistant-panel");
  var assistantLaunch = document.getElementById("assistant-launch");
  if (assistantForm && document.getElementById("assistant-messages")) {
    var closeButton = document.getElementById("assistant-close");
    var openAssistant = function (open) {
      if (!assistantPanel || !assistantLaunch) return;
      assistantPanel.hidden = !open;
      assistantLaunch.setAttribute("aria-expanded", String(open));
      if (open) document.getElementById("assistant-input").focus();
    };
    if (assistantLaunch) assistantLaunch.addEventListener("click", function () {
      openAssistant(assistantPanel.hidden);
    });
    if (closeButton) closeButton.addEventListener("click", function () { openAssistant(false); });

    var messagesElement = document.getElementById("assistant-messages");
    var storageKey = "cloudsec-chat-v1-user-" + assistantForm.querySelector('[name="csrf_token"]').dataset.userId;
    var chatHistory = [];
    try { chatHistory = JSON.parse(localStorage.getItem(storageKey) || "[]"); } catch (_) { chatHistory = []; }
    if (!Array.isArray(chatHistory)) chatHistory = [];
    chatHistory = chatHistory.filter(function (item) { return item && (item.role === "user" || item.role === "assistant") && typeof item.content === "string"; }).slice(-12);
    var renderText = function (text) {
      var escaped = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      return escaped.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
        .replace(/`([^`]+)`/g, "<code>$1</code>")
        .replace(/^[-*] (.+)$/gm, "• $1")
        .replace(/\n/g, "<br>");
    };
    var addMessage = function (text, kind) {
      var message = document.createElement("p");
      message.className = "assistant-message assistant-" + kind;
      if (kind === "response") message.innerHTML = renderText(text);
      else message.textContent = text;
      messagesElement.appendChild(message);
      messagesElement.scrollTop = messagesElement.scrollHeight;
      return message;
    };
    // Avoid replaying stale or overly long conversations into a fresh page view.
    // History remains available when the user explicitly chooses to restore it.
    var restoreButton = document.getElementById("assistant-restore");
    if (restoreButton && chatHistory.length) restoreButton.hidden = false;
    if (restoreButton) restoreButton.addEventListener("click", function () {
      messagesElement.innerHTML = "";
      chatHistory.forEach(function (item) { addMessage(item.content, item.role === "user" ? "user-message" : "response"); });
      restoreButton.hidden = true;
    });
    var saveHistory = function () { try { localStorage.setItem(storageKey, JSON.stringify(chatHistory)); } catch (_) {} };
    var clearHistory = function () {
      chatHistory = [];
      messagesElement.innerHTML = "";
      addMessage("Ask about your latest cloud audit or a general cloud security topic.", "response");
      saveHistory();
    };
    ["assistant-clear", "assistant-new"].forEach(function (id) {
      var control = document.getElementById(id);
      if (control) control.addEventListener("click", clearHistory);
    });
    if (assistantForm) {
      var input = document.getElementById("assistant-input");
      var sendButton = document.getElementById("assistant-send");
      input.addEventListener("keydown", function (event) {
        if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
          event.preventDefault();
          assistantForm.requestSubmit();
        }
      });
      assistantForm.addEventListener("submit", function (event) {
        event.preventDefault();
        var text = input.value.trim();
        if (!text || sendButton.disabled) return;
        addMessage(text, "user-message");
        chatHistory.push({ role: "user", content: text });
        chatHistory = chatHistory.slice(-12);
        input.value = "";
        input.disabled = true;
        sendButton.disabled = true;
        sendButton.textContent = "...";
        var loading = addMessage("CloudSec AI is reviewing your question and audit findings…", "notice");
        fetch("/assistant/chat", {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": assistantForm.querySelector('[name="csrf_token"]').value
          },
          body: JSON.stringify({ message: text, history: chatHistory.slice(0, -1) })
        })
          .then(function (response) {
            return response.json().then(function (data) {
              if (!response.ok) throw new Error(data.error || "The assistant could not reply.");
              return data;
            });
          })
          .then(function (data) {
            loading.remove();
            addMessage(data.reply, "response");
            chatHistory.push({ role: "assistant", content: data.reply });
            chatHistory = chatHistory.slice(-12);
            saveHistory();
          })
          .catch(function (error) { loading.remove(); addMessage(error.message, "notice"); chatHistory.pop(); saveHistory(); })
          .then(function () {
            input.disabled = false;
            sendButton.disabled = false;
            sendButton.textContent = "Send";
            input.focus();
          });
      });
      document.querySelectorAll(".assistant-suggestions [data-prompt]").forEach(function (button) {
        button.addEventListener("click", function () {
          input.value = button.dataset.prompt;
          assistantForm.requestSubmit();
        });
      });
    }
  }

  // Scans page: poll active scans and reload when one finishes.
  document.querySelectorAll('tr[data-active="true"]').forEach(function (row) {
    var timer = setInterval(function () {
      fetch("/scans/" + encodeURIComponent(row.dataset.scanId) + "/status", { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
          if (d && (d.status === "completed" || d.status === "failed")) {
            clearInterval(timer);
            window.location.reload();
          }
        })
        .catch(function () {});
    }, 4000);
  });
  // Clay Notification Bell Dropdown Toggle
  var bellBtn = document.getElementById("clay-bell-btn");
  var notifDropdown = document.getElementById("clay-notification-dropdown");
  var bellDot = document.getElementById("bell-dot");

  if (bellBtn && notifDropdown) {
    bellBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      var isHidden = notifDropdown.hasAttribute("hidden");
      if (isHidden) {
        notifDropdown.removeAttribute("hidden");
        bellBtn.setAttribute("aria-expanded", "true");
        if (bellDot) bellDot.style.display = "none";
      } else {
        notifDropdown.setAttribute("hidden", "");
        bellBtn.setAttribute("aria-expanded", "false");
      }
    });

    document.addEventListener("click", function (e) {
      if (!notifDropdown.contains(e.target) && !bellBtn.contains(e.target)) {
        notifDropdown.setAttribute("hidden", "");
        bellBtn.setAttribute("aria-expanded", "false");
      }
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !notifDropdown.hasAttribute("hidden")) {
        notifDropdown.setAttribute("hidden", "");
        bellBtn.setAttribute("aria-expanded", "false");
        bellBtn.focus();
      }
    });
  }

  // Account Popover Toggle & Logout Tracking
  var accountChip = document.getElementById("account-chip");
  var accountPopover = document.getElementById("account-popover");

  if (accountChip && accountPopover) {
    accountChip.addEventListener("click", function (e) {
      if (e.target.closest("#account-logout-btn, form")) return;
      e.stopPropagation();
      var isHidden = accountPopover.hasAttribute("hidden");
      if (isHidden) {
        accountPopover.removeAttribute("hidden");
        accountChip.setAttribute("aria-expanded", "true");
      } else {
        accountPopover.setAttribute("hidden", "");
        accountChip.setAttribute("aria-expanded", "false");
      }
    });

    document.addEventListener("click", function (e) {
      if (!accountPopover.contains(e.target) && !accountChip.contains(e.target)) {
        accountPopover.setAttribute("hidden", "");
        accountChip.setAttribute("aria-expanded", "false");
      }
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !accountPopover.hasAttribute("hidden")) {
        accountPopover.setAttribute("hidden", "");
        accountChip.setAttribute("aria-expanded", "false");
        accountChip.focus();
      }
    });
  }

  // Track logout submission for flash message on login page
  document.querySelectorAll('form[action*="logout"]').forEach(function (form) {
    form.addEventListener("submit", function () {
      sessionStorage.setItem("user_just_logged_out", "true");
    });
  });

  // Universal Clay Toast Notification
  function showClayToast(message, type) {
    var container = document.getElementById("clay-toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "clay-toast-container";
      container.style.cssText = "position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;";
      document.body.appendChild(container);
    }
    var toast = document.createElement("div");
    toast.className = "clay-toast" + (type ? " clay-toast-" + type : "");
    toast.textContent = message;
    toast.style.cssText = "pointer-events:auto;background:var(--clay-surface);color:var(--ink-primary);padding:12px 24px;border-radius:9999px;box-shadow:var(--clay-raised-shadow);font-family:var(--font-body);font-size:var(--fs-sm);font-weight:600;display:inline-flex;align-items:center;gap:8px;transition:opacity 0.25s ease, transform 0.25s ease;";
    container.appendChild(toast);
    setTimeout(function () {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(8px)";
      setTimeout(function () { toast.remove(); }, 300);
    }, 3000);
  }

  // Universal No-Dead-Clicks Interceptor
  document.addEventListener("click", function (e) {
    var target = e.target.closest("a, button");
    if (!target) return;

    var href = target.getAttribute("href");
    if (href === "#" || href === "javascript:void(0)" || href === "") {
      e.preventDefault();
      var label = target.textContent.trim() || target.getAttribute("aria-label") || target.getAttribute("title") || "Feature";
      showClayToast(label + " · Coming soon in the next release.", "info");
    }
  });

  // Topbar Live Search across all pages
  var searchInput = document.querySelector(".sunken-search-field input, .sunken-search input");
  if (searchInput) {
    searchInput.addEventListener("input", function () {
      var query = searchInput.value.trim().toLowerCase();
      var rows = document.querySelectorAll("table tbody tr");
      if (rows.length > 0) {
        rows.forEach(function (row) {
          if (!query) {
            row.hidden = false;
          } else {
            var text = row.textContent.toLowerCase();
            row.hidden = text.indexOf(query) === -1;
          }
        });
      }
    });

    searchInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        e.preventDefault();
        var query = searchInput.value.trim();
        var rows = document.querySelectorAll("table tbody tr");
        if (rows.length === 0 && query) {
          window.location.href = "/findings/?status=FAIL";
        } else if (query) {
          showClayToast("Filtered " + document.querySelectorAll("table tbody tr:not([hidden])").length + " matching item(s).");
        }
      }
    });
  }

  // Mobile navigation sidebar toggle
  var toggleBtn = document.getElementById("mobile-toggle");
  var sidebar = document.getElementById("app-sidebar");
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", function () {
      sidebar.classList.toggle("open");
    });
    document.addEventListener("click", function (e) {
      if (window.innerWidth <= 860 && sidebar.classList.contains("open") && !sidebar.contains(e.target) && !toggleBtn.contains(e.target)) {
        sidebar.classList.remove("open");
      }
    });
  }
})();

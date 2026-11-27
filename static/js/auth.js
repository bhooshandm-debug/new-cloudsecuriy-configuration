(function () {
  "use strict";

  document.querySelectorAll(".password-toggle").forEach(function (toggle) {
    var password = document.getElementById(toggle.getAttribute("aria-controls"));
    if (!password) return;

    toggle.addEventListener("click", function () {
      var showing = password.type === "password";
      password.type = showing ? "text" : "password";
      toggle.setAttribute("aria-label", showing ? "Hide password" : "Show password");
      toggle.setAttribute("aria-pressed", String(showing));
    });
  });
  // Show clear logout confirmation message if redirected from logout
  if (sessionStorage.getItem("user_just_logged_out") === "true") {
    sessionStorage.removeItem("user_just_logged_out");
    var card = document.querySelector(".login-card, .register-card");
    if (card) {
      var alert = document.createElement("div");
      alert.className = "flash-alert flash-info logout-banner";
      alert.innerHTML = '<span class="flash-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></span><span class="flash-message">You have been logged out successfully.</span>';
      var title = card.querySelector(".login-title");
      if (title) {
        card.insertBefore(alert, title);
      } else {
        card.insertBefore(alert, card.firstChild);
      }
    }
  }
})();

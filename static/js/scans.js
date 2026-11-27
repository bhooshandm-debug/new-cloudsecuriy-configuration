(function () {
  "use strict";

  var activeRows = Array.prototype.slice.call(document.querySelectorAll('tr[data-active="true"][data-status-url]'));
  if (activeRows.length) {
    var formatElapsed = function (seconds) {
      var minutes = Math.floor(seconds / 60);
      var remainder = seconds % 60;
      return minutes ? minutes + "m " + remainder + "s elapsed" : remainder + "s elapsed";
    };
    var pollRow = function (row) {
      fetch(row.dataset.statusUrl, { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then(function (response) {
          if (!response.ok) throw new Error("Status request failed");
          return response.json();
        })
        .then(function (scan) {
          var status = row.querySelector(".badge");
          var progress = row.querySelector("[data-scan-progress]");
          var cells = row.querySelectorAll("td");
          if (status) {
            status.className = "badge st-" + scan.status;
            status.textContent = scan.status;
          }
          if (progress && (scan.status === "pending" || scan.status === "running")) {
            progress.textContent = (scan.status === "pending" ? "Waiting for a scan worker · " : "Checking cloud configuration · ") + formatElapsed(scan.elapsed);
          }
          if (cells.length >= 6) {
            cells[4].textContent = scan.total;
            cells[5].textContent = scan.failed;
          }
          if (scan.status !== "pending" && scan.status !== "running") {
            window.location.reload();
            return;
          }
          window.setTimeout(function () { pollRow(row); }, 3000);
        })
        .catch(function () {
          window.setTimeout(function () { pollRow(row); }, 8000);
        });
    };
    activeRows.forEach(pollRow);
  }

  var radar = document.querySelector(".scans-radar-stage");
  if (!radar) return;

  var reset = function () {
    radar.style.removeProperty("--radar-tilt-x");
    radar.style.removeProperty("--radar-tilt-y");
    radar.style.setProperty("--radar-pointer-x", "50%");
    radar.style.setProperty("--radar-pointer-y", "50%");
  };

  radar.addEventListener("pointermove", function (event) {
    if (event.pointerType === "touch") return;
    var bounds = radar.getBoundingClientRect();
    var x = Math.max(0, Math.min(1, (event.clientX - bounds.left) / bounds.width));
    var y = Math.max(0, Math.min(1, (event.clientY - bounds.top) / bounds.height));
    radar.style.setProperty("--radar-tilt-x", ((0.5 - x) * 20).toFixed(1) + "deg");
    radar.style.setProperty("--radar-tilt-y", ((y - 0.5) * 14).toFixed(1) + "deg");
    radar.style.setProperty("--radar-pointer-x", (x * 100).toFixed(1) + "%");
    radar.style.setProperty("--radar-pointer-y", (y * 100).toFixed(1) + "%");
  });

  radar.addEventListener("pointerleave", reset);
  radar.addEventListener("blur", reset);
})();

(function () {
  function setup() {
    // Mode tabs
    var tabs = document.querySelectorAll('input[name="mode"]');
    var panels = document.querySelectorAll(".mode-panel");
    function update() {
      var checked = document.querySelector('input[name="mode"]:checked');
      var mode = checked ? checked.value : "directory";
      panels.forEach(function (p) {
        p.style.display = p.dataset.mode === mode ? "" : "none";
      });
    }
    tabs.forEach(function (t) { t.addEventListener("change", update); });
    update();
    // File input display
    var fileInput = document.getElementById("zip_file");
    var nameDisplay = document.getElementById("zip_file_name");
    if (fileInput && nameDisplay) {
      fileInput.addEventListener("change", function () {
        if (fileInput.files && fileInput.files.length > 0) {
          nameDisplay.textContent = fileInput.files[0].name +
            " (" + Math.round(fileInput.files[0].size / 1024) + " KB)";
          nameDisplay.classList.remove("muted");
        } else {
          nameDisplay.textContent = "No file selected";
          nameDisplay.classList.add("muted");
        }
      });
    }
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setup);
  } else {
    setup();
  }
})();

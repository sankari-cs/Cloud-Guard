(function () {
  function setup() {
    var btn = document.getElementById("toggle-password");
    var input = document.getElementById("password");
    if (!btn || !input) return;
    btn.addEventListener("click", function () {
      var hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      btn.textContent = hidden ? "Hide" : "Show";
      btn.setAttribute("aria-pressed", String(hidden));
      input.focus();
    });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setup);
  } else {
    setup();
  }
})();

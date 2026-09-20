;(function () {
  var themeId = localStorage.getItem("mergen-theme-id")
  if (!themeId) return

  var scheme = localStorage.getItem("mergen-color-scheme") || "system"
  var isDark = scheme === "dark" || (scheme === "system" && matchMedia("(prefers-color-scheme: dark)").matches)
  var mode = isDark ? "dark" : "light"

  document.documentElement.dataset.theme = themeId
  document.documentElement.dataset.colorScheme = mode

  if (themeId === "cs-1") return

  var css = localStorage.getItem("mergen-theme-css-" + themeId + "-" + mode)
  if (css) {
    var style = document.createElement("style")
    style.id = "cs-theme-preload"
    style.textContent =
      ":root{color-scheme:" +
      mode +
      ";--text-mix-blend-mode:" +
      (isDark ? "plus-lighter" : "multiply") +
      ";" +
      css +
      "}"
    document.head.appendChild(style)
  }
})()

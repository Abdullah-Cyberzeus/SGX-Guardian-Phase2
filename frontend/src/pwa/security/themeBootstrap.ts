export function applySavedTheme() {
  try {
    const saved = localStorage.getItem("sgx-theme");
    if (saved === "light") {
      document.documentElement.classList.remove("dark");
      return;
    }
  } catch {
    // Keep the default dark shell if browser storage is unavailable.
  }
  document.documentElement.classList.add("dark");
}

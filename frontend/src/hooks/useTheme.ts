import { useEffect, useState } from "react";

export type Theme = "light" | "dark";
const key = "netpolicy-theme";

function savedTheme(): Theme | null {
  try {
    const value = localStorage.getItem(key);
    return value === "light" || value === "dark" ? value : null;
  } catch {
    return null;
  }
}

function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#101815" : "#f4f6f3");
}

export function useTheme() {
  const [preference, setPreference] = useState<Theme | null>(savedTheme);
  const [systemDark, setSystemDark] = useState(() => window.matchMedia("(prefers-color-scheme: dark)").matches);
  const theme = preference ?? (systemDark ? "dark" : "light");

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => setSystemDark(media.matches);
    onChange();
    media.addEventListener("change", onChange);
    const onStorage = (event: StorageEvent) => {
      if (event.key === key || event.key === null) setPreference(savedTheme());
    };
    window.addEventListener("storage", onStorage);
    return () => {
      media.removeEventListener("change", onChange);
      window.removeEventListener("storage", onStorage);
    };
  }, []);

  useEffect(() => applyTheme(theme), [theme]);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setPreference(next);
    applyTheme(next);
    try { localStorage.setItem(key, next); } catch { /* Keep this tab usable without storage. */ }
  }

  return { theme, toggleTheme };
}

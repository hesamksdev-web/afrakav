import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

const STORAGE_KEY = "afra-theme";

export function applyStoredTheme() {
  const dark = (localStorage.getItem(STORAGE_KEY) ?? "dark") === "dark";
  document.documentElement.classList.toggle("dark", dark);
}

export default function ThemeToggle() {
  const [dark, setDark] = useState(
    () => (localStorage.getItem(STORAGE_KEY) ?? "dark") === "dark",
  );

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem(STORAGE_KEY, dark ? "dark" : "light");
  }, [dark]);

  return (
    <button
      type="button"
      onClick={() => setDark(d => !d)}
      title={dark ? "حالت روشن" : "حالت تیره"}
      aria-label={dark ? "حالت روشن" : "حالت تیره"}
      className="flex items-center justify-center w-7 h-7 rounded border border-border text-muted-foreground hover:text-primary hover:border-primary/30 transition-colors"
    >
      {dark ? <Sun size={13} /> : <Moon size={13} />}
    </button>
  );
}

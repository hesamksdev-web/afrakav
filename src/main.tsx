import { createRoot } from "react-dom/client";
import App from "./app/App.tsx";
import { applyStoredTheme } from "./app/components/ThemeToggle.tsx";
import "./styles/index.css";

// Set the .dark class before the first paint to avoid a theme flash.
applyStoredTheme();

createRoot(document.getElementById("root")!).render(<App />);

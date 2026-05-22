import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

// Background image lives in public/b1.jpg — webpack must not resolve it from src/styles.css
const publicUrl = (process.env.PUBLIC_URL || "").replace(/\/$/, "");
document.documentElement.style.setProperty(
  "--page-bg-image",
  `url("${publicUrl}/b1.jpg")`
);

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

import "./globals.css";
import { ThemeProvider } from "./context/ThemeContext";

export const metadata = {
  title: "Online Code Platform",
  description: "Write, execute, and review code securely",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  );
}
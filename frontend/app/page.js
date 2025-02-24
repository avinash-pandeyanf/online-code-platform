"use client";

import { useState, useEffect } from "react";
import CodeEditor from "./components/CodeEditor";
import Header from "./components/Header";
import { useRouter } from "next/navigation";
import { useTheme } from "./context/ThemeContext";
import { API_ENDPOINTS } from "./config/api";

export default function Home() {
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("javascript");
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");
  const [executionTime, setExecutionTime] = useState(0);
  const [submissions, setSubmissions] = useState([]);
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const { theme, toggleTheme } = useTheme();

  // Enhanced authentication check
  useEffect(() => {
    const checkAuth = () => {
      const token = localStorage.getItem("token");
      if (!token) {
        router.replace("/login");
      } else {
        fetchSubmissions();
      }
    };

    checkAuth();
  }, [router]);

  // Handle code execution
  const handleExecute = async () => {
    setLoading(true);
    const token = localStorage.getItem("token");
    try {
      const res = await fetch(API_ENDPOINTS.execute, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        credentials: 'include',
        body: JSON.stringify({ code, language }),
      });
      const data = await res.json();
      setLoading(false);
      if (res.ok) {
        setOutput(data.output || "");
        setError(data.error || "");
        setExecutionTime(data.executionTime || 0);
        fetchSubmissions(); // Refresh submissions after execution
      } else {
        setError(data.message);
      }
    } catch (err) {
      setError("Failed to connect to the server.");
      setLoading(false);
    }
  };

  // Fetch past submissions
  const fetchSubmissions = async () => {
    const token = localStorage.getItem("token");
    try {
      const res = await fetch(API_ENDPOINTS.submissions, {
        headers: { 
          Authorization: `Bearer ${token}` 
        },
        credentials: 'include',
      });
      if (!res.ok) {
        throw new Error("Failed to fetch submissions");
      }
      const data = await res.json();
      // Ensure data is an array; adjust based on your API response
      setSubmissions(Array.isArray(data) ? data : data.submissions || []);
    } catch (err) {
      setError("Failed to fetch submissions.");
      setSubmissions([]); // Reset to empty array on error
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900 dark:text-white">
      <Header />
      <main className="container mx-auto p-4">
        <h1 className="text-3xl font-bold mb-6">Online Code Execution Platform</h1>
        <div className="flex flex-col md:flex-row gap-6">
          <div className="flex-1">
            <select
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              className="mb-4 p-2 border rounded w-full bg-white dark:bg-gray-800 text-black dark:text-white"
            >
              <option value="javascript">JavaScript</option>
              <option value="python">Python</option>
              <option value="java">Java</option>
              <option value="cpp">C++</option>
              <option value="ruby">Ruby</option>
            </select>
            <CodeEditor value={code} onChange={setCode} language={language} />
            <button
              onClick={handleExecute}
              disabled={loading}
              className="mt-4 bg-blue-500 text-white p-2 rounded w-full hover:bg-blue-600 disabled:opacity-50"
            >
              {loading ? "Executing..." : "Execute"}
            </button>
          </div>
          <div className="flex-1">
            <h2 className="text-xl font-semibold mb-2">Output</h2>
            <pre className="bg-gray-200 dark:bg-gray-800 p-4 rounded">{output}</pre>
            <h2 className="text-xl font-semibold mb-2 mt-4">Error</h2>
            <pre className="bg-red-100 dark:bg-red-900 p-4 rounded">{error}</pre>
            <h2 className="text-xl font-semibold mb-2 mt-4">Execution Time</h2>
            <p>{executionTime} ms</p>
          </div>
        </div>
        <div className="mt-6">
          <h2 className="text-xl font-semibold mb-2">Past Submissions</h2>
          {submissions.length > 0 ? (
            <ul className="list-disc pl-5">
              {submissions.map((sub) => (
                <li key={sub.id} className="dark:text-gray-300">
                  {sub.language}: {sub.output || sub.error} ({sub.executionTime} ms)
                </li>
              ))}
            </ul>
          ) : (
            <p className="dark:text-gray-300">No submissions yet.</p>
          )}
        </div>
      </main>
    </div>
  );
}
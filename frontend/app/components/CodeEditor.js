import MonacoEditor from '@monaco-editor/react';

export default function CodeEditor({ value, onChange, language }) {
  return (
    <MonacoEditor
      height="500px"
      language={language}
      value={value}
      onChange={onChange}
      theme="vs-dark"
      options={{ minimap: { enabled: false } }}
    />
  );
}
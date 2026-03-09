import React from 'react';
import Editor from '@monaco-editor/react';

interface Props {
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
  height?: string;
}

export default function CodeEditorPanel({ value, onChange, readOnly = false, height = '100%' }: Props) {
  return (
    <div className="h-full w-full overflow-hidden" style={{ height }}>
      <Editor
        height={height}
        defaultLanguage="sol"
        value={value}
        onChange={v => onChange(v ?? '')}
        theme="vs-dark"
        options={{
          readOnly,
          fontSize: 13,
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontLigatures: true,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          lineNumbers: 'on',
          renderLineHighlight: 'line',
          padding: { top: 16, bottom: 16 },
          smoothScrolling: true,
          cursorBlinking: 'smooth',
          bracketPairColorization: { enabled: true },
          wordWrap: 'on',
        }}
      />
    </div>
  );
}

import React, { useRef, useEffect } from 'react';
import Editor, { OnMount } from '@monaco-editor/react';

interface Props {
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
  height?: string;
  selectedVulnerability?: { lineNumber?: number; line?: number } | null;
}

export default function CodeEditorPanel({ value, onChange, readOnly = false, height = '100%', selectedVulnerability }: Props) {
  const editorRef = useRef<any>(null);
  const decorationsRef = useRef<string[]>([]); // Track decoration IDs

  const handleEditorDidMount: OnMount = (editor) => {
    editorRef.current = editor;
  };

  useEffect(() => {
    if (!editorRef.current) return;

    // Phase 2: Robust Decoration Management
    // Safely remove ALL tracked decorations from the previous cycle
    if (decorationsRef.current.length > 0) {
      editorRef.current.deltaDecorations(decorationsRef.current, []);
      decorationsRef.current = [];
    }

    const line = selectedVulnerability?.lineNumber || selectedVulnerability?.line;

    if (line) {
      editorRef.current.revealLineInCenter(line, 0);

      // Apply and store the new decoration ID
      const newDecorations = editorRef.current.deltaDecorations([], [
        {
          range: { startLineNumber: line, startColumn: 1, endLineNumber: line, endColumn: 1 },
          options: {
            isWholeLine: true,
            className: 'monaco-line-highlight',
            glyphMarginClassName: 'monaco-glyph-margin',
            linesDecorationsClassName: 'monaco-line-decoration',
          },
        },
      ]);
      
      decorationsRef.current = newDecorations;
    }
  }, [selectedVulnerability]);

  return (
    <div className="h-full w-full overflow-hidden" style={{ height }}>
      <style dangerouslySetInnerHTML={{ __html: `
        .monaco-line-highlight { background: rgba(124, 58, 237, 0.2); }
        .monaco-glyph-margin { background: #7c3aed; width: 5px !important; }
        .monaco-line-decoration { border-left: 3px solid #7c3aed; }
      `}} />
      <Editor
        height={height}
        defaultLanguage="sol"
        value={value}
        onChange={v => onChange(v ?? '')}
        onMount={handleEditorDidMount}
        theme="vs-dark"
        options={{
          readOnly,
          fontSize: 13,
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontLigatures: true,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          lineNumbers: 'on',
          renderLineHighlight: 'all',
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

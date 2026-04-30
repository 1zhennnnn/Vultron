import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in component:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center p-8 bg-[#0f0f1a] border border-red-500/20 rounded-xl gap-4 text-center min-h-[200px]">
          <div className="w-12 h-12 rounded-full bg-red-500/10 flex items-center justify-center">
            <AlertTriangle className="text-red-500" size={24} />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white mb-1">
              {this.props.fallbackTitle || '組件載入錯誤'}
            </h3>
            <p className="text-xs text-slate-500 max-w-xs line-clamp-2">
              {this.state.error?.message || '發生了未知錯誤，請嘗試重整。'}
            </p>
          </div>
          <button 
            onClick={this.handleReset}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 text-xs font-medium transition-colors"
          >
            <RefreshCcw size={14} /> 重試組件
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

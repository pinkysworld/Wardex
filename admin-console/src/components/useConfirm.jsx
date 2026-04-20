import React, { useCallback, useRef, useState } from 'react';
import ConfirmDialog from './ConfirmDialog.jsx';

export function useConfirm() {
  const [state, setState] = useState(null);
  const resolverRef = useRef(null);

  const confirm = useCallback(
    (opts) =>
      new Promise((resolve) => {
        resolverRef.current = resolve;
        setState(opts || {});
      }),
    [],
  );

  const handleClose = useCallback((result) => {
    const resolve = resolverRef.current;
    resolverRef.current = null;
    setState(null);
    if (resolve) resolve(Boolean(result));
  }, []);

  const element = <ConfirmDialog state={state} onClose={handleClose} />;
  return [confirm, element];
}
import { useState, useEffect, useCallback } from 'react';

function normalizeOrder(defaultOrder, nextOrder) {
  const normalized = [];
  (Array.isArray(nextOrder) ? nextOrder : []).forEach((id) => {
    const widgetId = String(id || '').trim();
    if (!widgetId || !defaultOrder.includes(widgetId) || normalized.includes(widgetId)) return;
    normalized.push(widgetId);
  });
  defaultOrder.forEach((id) => {
    if (!normalized.includes(id)) normalized.push(id);
  });
  return normalized;
}

function normalizeHidden(order, nextHidden) {
  const normalized = [];
  (Array.isArray(nextHidden) ? nextHidden : []).forEach((id) => {
    const widgetId = String(id || '').trim();
    if (!widgetId || !order.includes(widgetId) || normalized.includes(widgetId)) return;
    normalized.push(widgetId);
  });
  return normalized;
}

function readStoredLayout(defaultOrder, storageKey) {
  let savedOrder = defaultOrder;
  try {
    const rawOrder = localStorage.getItem(storageKey);
    if (rawOrder) {
      savedOrder = normalizeOrder(defaultOrder, JSON.parse(rawOrder));
    }
  } catch {
    /* ignore */
  }

  let savedHidden = [];
  try {
    const rawHidden = localStorage.getItem(`${storageKey}_hidden`);
    if (rawHidden) {
      savedHidden = normalizeHidden(savedOrder, JSON.parse(rawHidden));
    }
  } catch {
    /* ignore */
  }

  return {
    order: savedOrder,
    hidden: new Set(savedHidden),
  };
}

export function useWidgetLayout(defaultOrder, storageKey = 'wardex_widget_layout') {
  const [layout, setLayout] = useState(() => readStoredLayout(defaultOrder, storageKey));
  const order = layout.order;
  const hidden = layout.hidden;

  useEffect(() => {
    localStorage.setItem(storageKey, JSON.stringify(order));
  }, [order, storageKey]);

  useEffect(() => {
    localStorage.setItem(storageKey + '_hidden', JSON.stringify([...hidden]));
  }, [hidden, storageKey]);

  const moveWidget = useCallback((fromId, toId) => {
    setLayout((prev) => {
      const next = [...prev.order];
      const fromIdx = next.indexOf(fromId);
      const toIdx = next.indexOf(toId);
      if (fromIdx < 0 || toIdx < 0) return prev;
      next.splice(fromIdx, 1);
      next.splice(toIdx, 0, fromId);
      return { ...prev, order: next };
    });
  }, []);

  const removeWidget = useCallback((id) => {
    setLayout((prev) => ({
      ...prev,
      hidden: new Set([...prev.hidden, id]),
    }));
  }, []);

  const restoreWidget = useCallback((id) => {
    setLayout((prev) => {
      const next = new Set(prev.hidden);
      next.delete(id);
      return { ...prev, hidden: next };
    });
  }, []);

  const resetLayout = useCallback(() => {
    setLayout({ order: defaultOrder, hidden: new Set() });
  }, [defaultOrder]);

  const applyLayout = useCallback(
    (nextLayout) => {
      const nextOrder = normalizeOrder(defaultOrder, nextLayout?.widgets || nextLayout?.order);
      const nextHidden = normalizeHidden(nextOrder, nextLayout?.hidden);
      setLayout({ order: nextOrder, hidden: new Set(nextHidden) });
    },
    [defaultOrder],
  );

  const visibleWidgets = order.filter((id) => !hidden.has(id));

  return {
    order: visibleWidgets,
    allWidgets: order,
    hidden,
    moveWidget,
    removeWidget,
    restoreWidget,
    resetLayout,
    applyLayout,
    snapshot: {
      widgets: [...order],
      hidden: [...hidden],
    },
  };
}

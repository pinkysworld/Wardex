import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import SearchPalette from '../components/SearchPalette';

// Mock the API module
vi.mock('../api', () => ({
  alerts: vi.fn().mockResolvedValue([]),
  incidents: vi.fn().mockResolvedValue([]),
  agents: vi.fn().mockResolvedValue([]),
  detectionRules: vi.fn().mockResolvedValue([]),
  feeds: vi.fn().mockResolvedValue([]),
}));

describe('SearchPalette', () => {
  const onClose = vi.fn();
  const onNavigate = vi.fn();

  beforeEach(() => {
    onClose.mockClear();
    onNavigate.mockClear();
    localStorage.clear();
  });

  it('renders nothing when closed', () => {
    const { container } = render(
      <SearchPalette open={false} onClose={onClose} onNavigate={onNavigate} />,
    );
    expect(container.querySelector('.search-palette')).not.toBeInTheDocument();
  });

  it('renders search input when open', () => {
    render(<SearchPalette open={true} onClose={onClose} onNavigate={onNavigate} />);
    expect(screen.getByPlaceholderText(/search/i)).toBeInTheDocument();
  });

  it('closes on ESC key', () => {
    render(<SearchPalette open={true} onClose={onClose} onNavigate={onNavigate} />);
    const input = screen.getByPlaceholderText(/search/i);
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledWith(false);
  });

  it('closes on backdrop click', () => {
    const { container } = render(
      <SearchPalette open={true} onClose={onClose} onNavigate={onNavigate} />,
    );
    const overlay = container.querySelector('.search-palette-overlay');
    if (overlay) fireEvent.click(overlay);
    expect(onClose).toHaveBeenCalledWith(false);
  });
});

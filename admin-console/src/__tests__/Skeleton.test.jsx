import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import { SkeletonRow, SkeletonCard } from '../components/Skeleton';

describe('Skeleton', () => {
  it('SkeletonRow renders correct number of cells', () => {
    const { container } = render(
      <table><tbody><SkeletonRow cols={4} /></tbody></table>
    );
    const cells = container.querySelectorAll('td');
    expect(cells.length).toBe(4);
  });

  it('SkeletonRow defaults to 5 columns', () => {
    const { container } = render(
      <table><tbody><SkeletonRow /></tbody></table>
    );
    const cells = container.querySelectorAll('td');
    expect(cells.length).toBe(5);
  });

  it('SkeletonCard renders with specified height', () => {
    const { container } = render(<SkeletonCard height={120} />);
    const div = container.querySelector('.skeleton');
    expect(div).toBeInTheDocument();
    expect(div.style.height).toBe('120px');
  });

  it('SkeletonCard defaults to 80px height', () => {
    const { container } = render(<SkeletonCard />);
    const div = container.querySelector('.skeleton');
    expect(div.style.height).toBe('80px');
  });
});

export const cleanSlitherDescription = (desc: string): string => {
  if (!desc) return '';
  return desc
    .replace(/\s*\([^)]*vultron_[^)]*\.sol[^)]*\)/g, '')
    .replace(/\s*\([^)]*\.sol#[\d-]+\)/g, '')
    .replace(/\s*\([^)]*\.sol:[^)]*\)/g, '')
    .trim();
};

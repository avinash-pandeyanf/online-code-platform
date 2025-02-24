const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export const API_ENDPOINTS = {
  login: `${API_BASE_URL}/login`,
  execute: `${API_BASE_URL}/execute`,
  submissions: `${API_BASE_URL}/submissions`,
};

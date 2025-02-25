const config = {
    API_URL: process.env.NODE_ENV === 'production' 
      ? 'https://online-code-platform.onrender.com'
      : 'http://localhost:3001'
  };
  
  export default config;
  
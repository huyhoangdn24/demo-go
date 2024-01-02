import React, { useState } from 'react';
import { Link } from 'react-router-dom';

function Index() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const handleLogin = () => {
    setIsLoggedIn(true);
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
  };

  return (
    <div>
      <header>
        <h1>Header</h1>
        {isLoggedIn ? (
          <Link to="/" onClick={handleLogout}>Logout</Link>
        ) : (
          <Link to="/login" onClick={handleLogin}>Login</Link>
        )}
      </header>
      <div>
        <h2>Index</h2>
      </div>
    </div>
  );
}

export default Index;

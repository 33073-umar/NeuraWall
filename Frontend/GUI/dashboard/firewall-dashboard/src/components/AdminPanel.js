import React, { useState } from 'react';

const AdminPanel = () => {
  const [accounts, setAccounts] = useState([]); // This will hold the list of user accounts

  // Function to create a new account (this can be modified with more details)
  const createAccount = (newAccount) => {
    setAccounts([...accounts, newAccount]);
  };

  // Function to delete an account
  const deleteAccount = (accountId) => {
    setAccounts(accounts.filter(account => account.id !== accountId));
  };

  return (
    <div>
      <h1>Admin Panel</h1>
      <div>
        <h2>Create Account</h2>
        {/* Add more form fields for account creation */}
        <button onClick={() => createAccount({ id: accounts.length + 1, name: "New User" })}>Create Account</button>
      </div>
      <div>
        <h2>Manage Accounts</h2>
        <ul>
          {accounts.map(account => (
            <li key={account.id}>
              {account.name} 
              <button onClick={() => deleteAccount(account.id)}>Delete</button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default AdminPanel;

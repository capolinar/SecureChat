import logo from './logo.svg';
import './App.css';

function App() {
  return (
    <div className="App">
      <h1>
		Welcome to our Secure Chat App
	  </h1>
	  <p>
		Please enter your information below
	  </p>

	  <form>
        <div className="input-group">
          <label htmlFor="name">Name</label>
          <input type="text" id="name" />
        </div>
        <div className="input-group">
          <label htmlFor="ip">Chat IP:</label>
          <input type="text" id="ip" />
        </div>
        <button type="submit" className="submit-btn">
          Submit
        </button>
      </form>
    </div>
  );
}

export default App;

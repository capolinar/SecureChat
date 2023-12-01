import {useState} from 'react';
import './App.css';

var isSignedIn = false;

function App() {

  return (
    <div className="App">
      <header>
	      <h1>Secure Chat App</h1>
        <button type="submit" className="signOutBtn" onClick={() => {isSignedIn = false}}>
          Sign Out
        </button>
      </header>
      <body>
        {/* {isSignedIn ? <Chat/> : <SignInPage/>} */}
        <SignInPage/>
      </body>
    </div>
  );
}
function SignInPage(){
   

  return (
    <div className="App">
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
        <button type="submit" className="signInBtn" onClick={() => {isSignedIn = true}}>
          Submit
        </button>
      </form>
    </div>
    )
  } 
function Chat(){
    return(
      <div>
        <div className="messageBar">
          <form >
            <input className="sendMsgInp"placeholder="Send a secure message"/>
            <button className="sendMsgBtn">Send</button>
          </form>
        </div>
      </div>
    )
  }

export default App;

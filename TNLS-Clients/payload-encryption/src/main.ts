import './style.css'
import { setupConnect } from './connect'
import { setupSubmit } from './submit'

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
<header>
  <h1>Atbash Labs</h1>
  <div id="links">
    <a href="">
    <div class="card">
      Whitepaper
    </div>
    </a>
    <a href="">
    <div class="card">
      GitHub
    </div>
    </a>
    <a href="">
    <div class="card">
      Docs
    </div>
    </a>
  </div>
</header>
  <div>
    <h2>Sample Application: Random Number Generation using Encrypted Payloads</h2>
    <div id="form">
      <button id="submit">Submit</button>
      <form name="inputForm">
      <br>
      <label for="input1">Number of Random Words (up to 2000)</label>
      <input type="number" placeholder="50" id="input1" name="input1" />
      <br>
      <br>
      <label for="input2">Callback gas limit</label>
      <input type="number" placeholder="300000" id="input2" name="input2" />
      <br>

    </div>
    <div id="preview" style="word-wrap: break-word;">
    </div>
    <div class="card">
    </div>
  </div>
`
setupSubmit(document.querySelector<HTMLButtonElement>('#submit')!)
setupConnect(document.querySelector<HTMLButtonElement>('#connect')!)
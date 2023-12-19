import './style.css'
import { setupConnect } from './connect'
import { setupSubmit } from './submit'

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
<header>
  <h1>Fortress Labs</h1>
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
    <h2>Sample Application: Random Number Generation</h2>
    <div id="form">
      <button id="submit">Submit</button>

    </div>
    <div id="preview" style="word-wrap: break-word;">
    </div>
    <div class="card">
    </div>
  </div>
`
setupSubmit(document.querySelector<HTMLButtonElement>('#submit')!)
setupConnect(document.querySelector<HTMLButtonElement>('#connect')!)
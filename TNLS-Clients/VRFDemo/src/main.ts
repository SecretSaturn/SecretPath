import './style.css'
import { setupConnect } from './connect'
import { setupSubmit } from './submit'

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
<header>
  <h1>Secret VRF on Ethereum</h1>
</header>
  <div>
    <h2>Sample Application: Roll the Dice!</h2>
    <h2>Random Number Generation using Secret VRF, bridged into EVM.</h2>
    <h3>This demo generates 2000 verifiable random numbers in just one transaction.</h3>
    <div id="form">
      <button id="submit">Roll the dice </button>
      <form name="inputForm">

    </div>
    <div id="preview" style="word-wrap: break-word;">
    </div>
    <div class="card">
    </div>
  </div>
`
setupSubmit(document.querySelector<HTMLButtonElement>('#submit')!)
setupConnect(document.querySelector<HTMLButtonElement>('#connect')!)
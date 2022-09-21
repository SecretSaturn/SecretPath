import { ethers } from 'ethers';

export function setupConnect(element: HTMLButtonElement) {
  element.innerHTML = `Connect`
  let myAddress : string
  const connect = async () => {
    // @ts-ignore
    const provider = new ethers.providers.Web3Provider(window.ethereum);
    [myAddress] = await provider.send("eth_requestAccounts", []);
    element.innerHTML = `Connected`
    document.querySelector<HTMLDivElement>('#account')!.innerHTML = `
      <p>Connected account: ${myAddress}</p>
    `
  }
  element.addEventListener('click', () => connect())
}
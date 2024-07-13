const anchor = require("@coral-xyz/anchor");
const { SystemProgram } = anchor.web3;

module.exports = async function (provider) {
  // Configure client to use the provider.
  anchor.setProvider(provider);

  // Load the program
  const program = anchor.workspace.MyProgram;

  // Generate a new keypair for the gateway state account
  const gatewayState = anchor.web3.Keypair.generate();

  // Determine the rent-exempt balance for the new account
  const lamports = await provider.connection.getMinimumBalanceForRentExemption(
    8 + 8 + 8 + 9000
  );

  // Create the transaction to initialize the account
  const transaction = new anchor.web3.Transaction().add(
    anchor.web3.SystemProgram.createAccount({
      fromPubkey: provider.wallet.publicKey,
      newAccountPubkey: gatewayState.publicKey,
      lamports,
      space: 8 + 8 + 8 + 9000,
      programId: program.programId,
    }),
    
    program.instruction.initialize({
      accounts: {
        gatewayState: gatewayState.publicKey,
        user: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      },
      signers: [gatewayState],
    })
  );

  // Send the transaction
  await provider.sendAndConfirm(transaction, [gatewayState]);

  console.log("Gateway state initialized:", gatewayState.publicKey.toString());
};


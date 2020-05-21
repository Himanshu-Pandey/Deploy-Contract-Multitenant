let process = require("process");
let Web3 = require('web3');
let HttpHeaderProvider = require('httpheaderprovider');
let request = require("request");
const quorumjs = require("quorum-js");
const EthereumTx = require('ethereumjs-tx').Transaction;
let web3 = new Web3();
let tesseraKeys = {
    'A1': 'xl1VWgypeSb3MBC2CLLadaNysHH/0OnsVDRmotCekmM=',
    'A2': 'H1uDNuCx8OnJvwqrLgwGd5/ZyDP31FMHRL5yB2d60ks=',
    'B1': 'C52chAyQi2ItS1vA5yjhTtPfqVM/HstElkZ+M+8c4FQ=',
    'C1': 'kOb5ZijYS9v/ZUqNhW3mOYlpid3quYF9O75XGm7Cn1U='
};
let simpleContractABI = [{ "constant": false, "inputs": [{ "name": "x", "type": "uint256" }], "name": "set", "outputs": [], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": true, "inputs": [], "name": "get", "outputs": [{ "name": "retVal", "type": "uint256" }], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": false, "inputs": [{ "name": "a", "type": "address" }, { "name": "x", "type": "uint256" }], "name": "setAnother", "outputs": [], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "inputs": [{ "name": "initVal", "type": "uint256" }], "payable": false, "stateMutability": "nonpayable", "type": "constructor" }];
let simpleContractByteCode = '0x608060405234801561001057600080fd5b506040516020806102258339810180604052602081101561003057600080fd5b810190808051906020019092919050505080600081905550506101cd806100586000396000f3fe608060405234801561001057600080fd5b506004361061005e576000357c01000000000000000000000000000000000000000000000000000000009004806360fe47b1146100635780636d4ce63c14610091578063ad12f8aa146100af575b600080fd5b61008f6004803603602081101561007957600080fd5b81019080803590602001909291905050506100fd565b005b610099610107565b6040518082815260200191505060405180910390f35b6100fb600480360360408110156100c557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610110565b005b8060008190555050565b60008054905090565b60008290508073ffffffffffffffffffffffffffffffffffffffff166360fe47b1836040518263ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040180828152602001915050600060405180830381600087803b15801561018457600080fd5b505af1158015610198573d6000803e3d6000fd5b5050505050505056fea165627a7a72305820f5e61faad8a209cc7b9571e5ca5d7b93064a17d1ccfa1e26e22e3675ebf7331e0029';
let keystore = { "address": "ed9d02e382b34818e88b88a309c7fe71e65f419d", "crypto": { "cipher": "aes-128-ctr", "ciphertext": "4e77046ba3f699e744acb4a89c36a3ea1158a1bd90a076d36675f4c883864377", "cipherparams": { "iv": "a8932af2a3c0225ee8e872bc0e462c11" }, "kdf": "scrypt", "kdfparams": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "8ca49552b3e92f79c51f2cd3d38dfc723412c212e702bd337a3724e8937aff0f" }, "mac": "6d1354fef5aa0418389b1a5d1f5ee0050d7273292a1171c51fd02f9ecff55264" }, "id": "a65d1ac3-db7e-445d-a1cc-b6c5eeaa05e0", "version": 3 };
let headers = {};
var token_A1_A2 = {
    method: 'POST',
    url: 'https://localhost:4444/oauth2/token',
    headers:
        { 'content-type': 'application/x-www-form-urlencoded' },
    form:
    {
        grant_type: 'client_credentials',
        client_id: 'Tenant_A',
        client_secret: 'foofoo',
        audience: 'Node1',
        scope: 'rpc://eth_* rpc://rpc_modules private://0x0/_/contracts?owned.eoa=0x0&party.tm=xl1VWgypeSb3MBC2CLLadaNysHH%2F0OnsVDRmotCekmM%3D private://0x0/_/contracts?owned.eoa=0x0&party.tm=H1uDNuCx8OnJvwqrLgwGd5%2FZyDP31FMHRL5yB2d60ks%3D'
    }
};

function getToken(callBack) {
    request(token_A1_A2, function (error, response, body) {
        if (error) throw new Error(error);
        headers = { "Authorization": `Bearer ${JSON.parse(body).access_token}` }
        callBack();
    });
}

function setWeb3ProviderWithHeader() {
    console.log("\nToken", headers.Authorization);
    var provider = new HttpHeaderProvider('https://localhost:22000', headers);
    web3.setProvider(provider);
    quorumjs.extend(web3);
}

function getFirstAccount() {
    return web3.eth.getAccounts().then((accounts) => {
        return accounts[0];
    });
}

async function deployContract(accountAddress, privateFor, privateFrom) {
    let contract = new web3.eth.Contract(simpleContractABI);
    let encodedABI = contract.deploy({
        data: simpleContractByteCode,
        arguments: [101]
    }).encodeABI();
    let nonce = await web3.eth.getTransactionCount(accountAddress);
    let tx = {
        nonce: web3.utils.toHex(nonce),
        from: accountAddress,
        gas: 100000000,
        gasPrice: 0,
        privateFor: privateFor,
        privateFrom: privateFrom,
        data: encodedABI
    }
    console.log(`\nTransaction to be send is : ${JSON.stringify(tx)}`);
    let decryptKey = web3.eth.accounts.decrypt(keystore, "");
    let bufferPK = new Buffer(decryptKey.privateKey.substring(2), 'hex');
    let transaction = new EthereumTx(tx);

    console.log(`\nSigning the transaction using key ${JSON.stringify(decryptKey)}`);
    transaction.sign(bufferPK);

    const signedHexPayload = "0x" + transaction.serialize().toString('hex');

    console.log('\nSaving data in tessera');
    request({
        method: 'POST',
        url: 'http://localhost:9080/storeraw',
        headers:
        {
            'content-type': 'application/json'
        },
        body: { payload: [signedHexPayload], from: [tesseraKeys.A1] },
        json: true
    }, function (error, response, body) {
        if (error) throw new Error(error);
        console.log(`\nData from tessera \nResponse Status: ${response.statusCode} \nBody : ${JSON.stringify(body)}`);
        console.log(`\nSending signed transaction`);

        //Send data to quorum
        web3.quorum.eth.sendRawPrivateTransaction(signedHexPayload, {
            "privateFor": privateFor,
            "privateFrom": privateFrom,
        });
    });
}

(async function () {
    process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0;
    getToken(async function () {
        console.log('\nSetting provider');
        setWeb3ProviderWithHeader();
        const account = await getFirstAccount();
        console.log(`\nAccount used for deploying contract is ${account}`);
        await deployContract(account, [tesseraKeys.A2], tesseraKeys.A1);
    });
})();

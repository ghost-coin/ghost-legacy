const PayeeAddr = "pYMJBNtUUEYrd9T2efvKA1jZz9E3JMTbW4";//Change this for mainnet,we may wanna change this later to give out hash160s for chainparams.
const Paymentamt = 1000;
const COIN = 100000000;
const paymenttimes = 1;
for (var i = 0;i<paymenttimes;i++)
    console.log(`${PayeeAddr},${Paymentamt * COIN}`);
const program = require("commander");
const fs = require("fs");
const nunjucks = require("nunjucks");


program.version("0.0.1");
program.option(
    "-t, --template <template>",
    "TendermintLightClient template file",
    "./contracts/TendermintLightClient.template"
);

program.option(
    "-o, --output <output-file>",
    "TendermintLightClient.sol",
    "./contracts/TendermintLightClient.sol"
)

program.option("--rewardForValidatorSetChange <rewardForValidatorSetChange>",
    "rewardForValidatorSetChange",
    "1e16"); //1e16

program.option("--initConsensusStateBytes <initConsensusStateBytes>",
    "init consensusState bytes, hex encoding, no prefix with 0x",
    "373135000000000000000000000000000000000000000000000000000000000000000000000000327ced57fb33ec6bf701dc2c9925670851499f7a9c0724f9d23b36b31f261164165883a8d5c3cabfaca83eae1c2e6cf3dd66928604801000aab8f2c07bef5524d6e31d5f72c1d488fae01727b020f36f7005061ebc98b96a4a9806bcdcf737d95a000000e8d4a51000");

program.option("--mock <mock>",
    "if use mock",
    false);

program.parse(process.argv);

const data = {
  initConsensusStateBytes: program.initConsensusStateBytes,
  rewardForValidatorSetChange: program.rewardForValidatorSetChange,
  mock: program.mock,
};
const templateString = fs.readFileSync(program.template).toString();
const resultString = nunjucks.renderString(templateString, data);
fs.writeFileSync(program.output, resultString);
console.log("TendermintLightClient file updated.");

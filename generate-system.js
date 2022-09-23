const program = require("commander");
const fs = require("fs");
const nunjucks = require("nunjucks");

program.version("0.0.1");
program.option(
    "-t, --template <template>",
    "system template file",
    "./contracts/System.template"
);

program.option(
    "-o, --output <output-file>",
    "System.sol",
    "./contracts/System.sol"
)
program.option("--mock <mock>",
    "if use mock",
    false);

program.option("--bscChainId <bscChainId>",
    "bscChainId",
    "02CA");

program.parse(process.argv);

const data = {
  fromChainId: program.fromChainId, // 这合约里面没有对应预留的模板变量
  bscChainId: program.bscChainId,
  mock: program.mock,
};
const templateString = fs.readFileSync(program.template).toString();
const resultString = nunjucks.renderString(templateString, data);
fs.writeFileSync(program.output, resultString);
console.log("System file updated.");

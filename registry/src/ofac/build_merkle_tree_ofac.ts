import * as fs from 'fs';
import { buildPassTree} from '../../../common/src/utils/passportTree'

async function passport() {
  const passports = JSON.parse(fs.readFileSync("../common/ofacdata/passport.json") as unknown as string)
  const tree = buildPassTree(passports);

  const serializedTree = tree.export();
  fs.writeFileSync("outputs/passport_tree.json", JSON.stringify(serializedTree));
  fs.copyFileSync("outputs/passport_tree.json", "../common/ofacdata/passport_tree.json");
  console.log("passport_tree.json written and copied in common/ofac!")
}

passport()
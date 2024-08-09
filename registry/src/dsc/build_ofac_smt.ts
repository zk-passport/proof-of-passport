import * as fs from 'fs';
import { buildSMT } from '../../../common/src/utils/ofacTree'

async function main() {
    let startTime = performance.now();
  
    const passports = JSON.parse(fs.readFileSync("../../../common/ofacdata/inputs/passports.json") as unknown as string)
    const names = JSON.parse(fs.readFileSync("../../../common/ofacdata/inputs/names.json") as unknown as string)

    const tree = buildSMT(passports,"passport");
    const nameDobTree = buildSMT(names,"name_dob");
    const nameTree1 = buildSMT(names,"name");
  
    console.log("Total passports processed are : ",tree[0] ," over ",passports.length )
    console.log("SMT for passports built in"+ tree[1] + "ms")
    console.log("Total names&dob processed are : ",nameDobTree[0] ," over ",names.length )
    console.log("SMT for names&dob built in " + nameDobTree[1] + "ms")
    console.log("Total names processed are : ",nameTree1[0] ," over ",names.length )
    console.log("SMT for names built in "+ nameTree1[1] + "ms")
    console.log('Total Time : ', performance.now() - startTime, 'ms')
  
    const passOfacJSON = tree[2].export()
    const nameDobOfacJSON = nameDobTree[2].export()
    const nameOfacJSON = nameTree1[2].export()
  
    fs.writeFileSync("../../../common/ofacdata/outputs/passportNoSMT.json", JSON.stringify(passOfacJSON));
    fs.writeFileSync("../../../common/ofacdata/outputs/nameDobSMT.json", JSON.stringify(nameDobOfacJSON));
    fs.writeFileSync("../../../common/ofacdata/outputs/nameSMT.json", JSON.stringify(nameOfacJSON));
}
  
main()
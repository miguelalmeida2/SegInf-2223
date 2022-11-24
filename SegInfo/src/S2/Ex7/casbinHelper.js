const { newEnforcer } = require('casbin');

async function enforce(s, o, a) {
    const enforcer = await newEnforcer('model.conf', 'policy.csv');
    r = await enforcer.enforce(s, o, a);
    return {res: r, sub: s, obj: o, act: a};
}

async function addRolesToUser(sub, roles) {
    const e = await enforcerPromise;
    await Promise.all(roles.map(role => e.addRoleForUser(sub, role)));
}

async function execute(decision) {
    console.log(decision);
    if (decision.res == true) {
      console.log("permit operation")
    } else {
      console.log("deny operation")
    }  
}

module.exports.execute = execute;
module.exports.enforce = enforce;
module.exports.addRolesToUser = addRolesToUser;
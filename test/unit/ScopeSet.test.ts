import { expect }   from "chai"
import ScopeSet from "../../src/isomorphic/ScopeSet"


describe("ScopeSet", () => {

    it('using "matches()" to test with RegExp', () => {
        const instance = new ScopeSet('scope1');
        expect(instance.matches(/^sc/)).to.be.true;
        expect(instance.matches(/^abc/)).to.be.false;
    });

    describe('add()', () => {
        it ('using "add" with empty ScopeSet', () => {
            const instance = new ScopeSet();
            expect(instance.toString(), 'Should be an empty string').to.equal('');
            expect(instance.toJSON(), 'Should be an empty array').to.deep.equal([]);
            instance.add('scope1');
            expect(instance.toString()).to.equal('scope1');
            expect(instance.toJSON()).to.deep.equal(['scope1']);
        });
    
        it ('using "add" with non-empty ScopeSet', () => {
            const instance = new ScopeSet('scope1 scope2');
            expect(instance.toString()).to.equal('scope1 scope2');
            expect(instance.toJSON()).to.deep.equal(['scope1', 'scope2']);
            const result = instance.add('scope3');
            expect(instance.toString()).to.equal('scope1 scope2 scope3');
            expect(instance.toJSON()).to.deep.equal(['scope1', 'scope2', 'scope3']);
            expect(result).to.be.true;
        });
    
        it ("ignores adding existing scopes and returns false", () => {
            const instance = new ScopeSet('scope1 scope2');
            const result = instance.add('scope1');
            expect(instance.toString()).to.equal('scope1 scope2');
            expect(instance.toJSON()).to.deep.equal(['scope1', 'scope2']);
            expect(result).to.be.false;
        });
    });

    describe('remove()', () => {
        it('using "remove" with empty ScopeSet', () => {
            const instance = new ScopeSet();
            expect(instance.toString(), 'Should be an empty string').to.equal('');
            expect(instance.toJSON(), 'Should be an empty array').to.deep.equal([]);
            const result = instance.remove('scope1');
            expect(result).to.be.false;
        });

        it('using "remove" with non-empty ScopeSet and existing scope', () => {
            const instance = new ScopeSet('scope1 scope2');
            expect(instance.toString()).to.equal('scope1 scope2');
            expect(instance.toJSON()).to.deep.equal(['scope1', 'scope2']);
            const result = instance.remove('scope1');
            expect(instance.toString()).to.equal('scope2');
            expect(instance.toJSON()).to.be.deep.equal(['scope2']);
            expect(result).to.be.true;
        });

        it('using "remove" with non-empty ScopeSet and non-existing scope', () => {
            const instance = new ScopeSet('scope1 scope2');
            expect(instance.toString()).to.equal('scope1 scope2');
            expect(instance.toJSON()).to.deep.equal(['scope1', 'scope2']);
            const result = instance.remove('scope3');
            expect(instance.toString()).to.equal('scope1 scope2');
            expect(instance.toJSON()).to.be.deep.equal(['scope1', 'scope2']);
            expect(result).to.be.false;
        });
    });

    describe('negotiate()', () => {
        it('grants launch/ scopes with query params when base scope is allowed', () => {
            const allowed = new ScopeSet('launch/questionnaire patient/Patient.r');
            const { grantedScopes, rejectedScopes } = allowed.negotiate(
                'launch/questionnaire?role=http://ns.electronichealth.net.au/smart/role/new patient/Patient.r'
            );
            expect(grantedScopes).to.include('launch/questionnaire?role=http://ns.electronichealth.net.au/smart/role/new');
            expect(grantedScopes).to.include('patient/Patient.r');
            expect(rejectedScopes).to.deep.equal([]);
        });

        it('rejects launch/ scopes with query params when base scope is not allowed', () => {
            const allowed = new ScopeSet('launch/patient patient/Patient.r');
            const { grantedScopes, rejectedScopes } = allowed.negotiate(
                'launch/questionnaire?role=http://ns.electronichealth.net.au/smart/role/new'
            );
            expect(grantedScopes).to.deep.equal([]);
            expect(rejectedScopes).to.include('launch/questionnaire?role=http://ns.electronichealth.net.au/smart/role/new');
        });

        it('grants launch/ scopes without query params via direct match', () => {
            const allowed = new ScopeSet('launch/questionnaire launch/patient');
            const { grantedScopes } = allowed.negotiate('launch/questionnaire');
            expect(grantedScopes).to.include('launch/questionnaire');
        });
    });

    describe('getInvalidSystemScopes()', () => {
        it('with a valid scopes', () => {
            expect(ScopeSet.getInvalidSystemScopes("system/Client.read")).to.equal('');
            expect(ScopeSet.getInvalidSystemScopes("system/Client.read system/Client.*")).to.equal('');
            expect(ScopeSet.getInvalidSystemScopes("system/Client.write system/*")).to.equal('');
            expect(ScopeSet.getInvalidSystemScopes("system/Patient.rs")).to.equal('');
            expect(ScopeSet.getInvalidSystemScopes("system/Observation.rs?category=laboratory")).to.equal('');
        });

        it('with invalid scopes', () => {
            expect(ScopeSet.getInvalidSystemScopes("system/client.read")).to.equal("system/client.read");
            expect(ScopeSet.getInvalidSystemScopes("system/Client.read System/Client.*")).to.equal('System/Client.*');
            expect(ScopeSet.getInvalidSystemScopes("system/Client.write system/Client.")).to.equal('system/Client.');
            expect(ScopeSet.getInvalidSystemScopes('System/* system/client')).to.equal('System/*');
            expect(ScopeSet.getInvalidSystemScopes("System/* system/Patient.rs")).to.equal('System/*');
            expect(ScopeSet.getInvalidSystemScopes("System/* system/Observation.rs?category=laboratory")).to.equal('System/*');
        });

        it('with empty string', () => {
            expect(ScopeSet.getInvalidSystemScopes('')).to.equal('');
            expect(ScopeSet.getInvalidSystemScopes()).to.equal('');
        });
    });
})

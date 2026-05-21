component extends="coldbox.system.testing.BaseModelTest" model="cbsecurity.models.jwt.JwtService" {

	/*********************************** LIFE CYCLE Methods ***********************************/

	function beforeAll(){
		super.setup();
	}

	function afterAll(){
	}

	/*********************************** BDD SUITES ***********************************/

	function run( testResults, testBox ){
		describe( "JwtService Epoch Conversion", function(){
			it( "toEpoch returns correct epoch seconds for a known UTC date", function(){
				var utcNewYear   = parseDateTime( "2024-01-01T00:00:00Z" );
				var epochSeconds = model.toEpoch( utcNewYear );
				expect( epochSeconds ).toBe( 1704067200 );
			} );

			it( "fromEpoch returns a date that round-trips through toEpoch", function(){
				var now_         = now();
				var epochSeconds = model.toEpoch( now_ );
				var roundTripped = model.fromEpoch( epochSeconds );
				expect( dateDiff( "s", now_, roundTripped ) ).toBeCloseTo( 0, 0 );
			} );

			it( "fromEpoch( 0 ) returns the epoch baseline", function(){
				var epochBaseline    = model.fromEpoch( 0 );
				var expectedBaseline = parseDateTime( "1970-01-01T00:00:00Z" );
				expect( dateDiff( "s", epochBaseline, expectedBaseline ) ).toBe( 0 );
			} );

			it( "toEpoch result is consistent with manual dateDiff calculation", function(){
				var testDate      = now();
				var toEpochResult = model.toEpoch( testDate );
				var manualEpoch   = dateDiff(
					"s",
					parseDateTime( "1970-01-01T00:00:00Z" ),
					testDate
				);
				expect( toEpochResult ).toBe( manualEpoch );
			} );

			it( "toEpoch result is within acceptable range for current time", function(){
				var now_         = now();
				var epochSeconds = model.toEpoch( now_ );
				expect( epochSeconds ).toBeGT( 1700000000 );
				expect( epochSeconds ).toBeLT( 2000000000 );
			} );

			it( "toEpoch and fromEpoch handle epoch zero correctly", function(){
				var epochZero     = 0;
				var dateFromEpoch = model.fromEpoch( epochZero );
				var backToEpoch   = model.toEpoch( dateFromEpoch );
				expect( backToEpoch ).toBe( epochZero );
			} );

			it( "toEpoch handles dates before epoch (negative epoch)", function(){
				var beforeEpoch  = parseDateTime( "1969-12-31T23:59:59Z" );
				var epochSeconds = model.toEpoch( beforeEpoch );
				expect( epochSeconds ).toBe( -1 );
			} );

			it( "fromEpoch handles negative epoch values", function(){
				var negativeEpoch = -1;
				var dateFromEpoch = model.fromEpoch( negativeEpoch );
				var expectedDate  = parseDateTime( "1969-12-31T23:59:59Z" );
				expect( dateDiff( "s", dateFromEpoch, expectedDate ) ).toBe( 0 );
			} );
		} );
	}

}

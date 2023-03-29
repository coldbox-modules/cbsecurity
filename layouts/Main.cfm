<cfoutput>
<!doctype html>
<html lang="en">
	<head>
		<!-- Required meta tags -->
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

		<!-- Bootstrap CSS -->
		<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">
		<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/bootstrap-icons.css">

		<title>ColdBox Security Visualizer</title>
		<style>
			[x-cloak] { display: none !important; }
			.nav-pills .nav-link.active {
				background-color: ##002f75;
			}
			.nav-link{
				color: ##737579;
			}
			.nav-link:hover{
				background-color: ##b0cefb;
			}
		</style>
	</head>

	<body>

		<nav class="navbar navbar-expand-lg bg-secondary bg-gradient">
			<div class="container-fluid">
				<a class="navbar-brand me-5 text-light" href="##">
					<i class="bi bi-shield-lock text-warning"></i>
					ColdBox Security Visualizer
				</a>

				<button
					class="navbar-toggler"
					type="button"
					data-bs-toggle="collapse"
					data-bs-target="##navbarNav"
					aria-controls="navbarNav"
					aria-expanded="false"
					aria-label="Toggle navigation">
					<span class="navbar-toggler-icon"></span>
				</button>

				<div class="collapse navbar-collapse" id="navbarNav">
					<ul class="navbar-nav text-light">
						<li class="nav-item me-2">
							<a
								class="nav-link active"
								aria-current="page"
								target="_blank"
								href="https://coldbox-security.ortusbooks.com/">Docs</a>
						</li>

						<li class="nav-item me-2">
							<a
								class="nav-link active"
								aria-current="page"
								target="_blank"
								href="https://www.ortussolutions.com/services/support/">Support</a>
						</li>

						<li class="nav-item me-2">
							<a
								class="nav-link active"
								aria-current="page"
								target="_blank"
								href="https://community.ortussolutions.com/">Discourse</a>
						</li>
					</ul>
				  </div>
			</div>
		</nav>

		<div class="container-fluid m-2 mt-4 mb-5">
			#renderView()#
		</div>

		<!--- Scripts --->
		<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js" integrity="sha384-oBqDVmMz9ATKxIep9tiCxS/Z9fNfEXiDAYTujMAeBAsjFuCZSmKbSSUnQlmh/jp3" crossorigin="anonymous"></script>
		<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.min.js" integrity="sha384-cuYeSxntonz0PPNlHhBs68uyIAVpIIOZZ5JqeqvYYIcEL727kskC66kF92t6Xl2V" crossorigin="anonymous"></script><script defer src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>
		<script>
			window.addEventListener( 'load', ( event ) => {
				const aTooltips = document.querySelectorAll( '[data-bs-toggle="tooltip"]' );
				const tooltipList = [...aTooltips ].map( el => new bootstrap.Tooltip( el ) );
			} );
		</script>
	</body>
</html>
</cfoutput>

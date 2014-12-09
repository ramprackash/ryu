var url = "http://" + location.hostname + ":8080";

function bandwidthTest() {
    var h1_lpBandwidthBody = document.getElementById('paper-container-h1_lpBandwidth');
    var h2_lpBandwidthBody = document.getElementById('paper-container-h2_lpBandwidth');
    var h1_dpBandwidthBody = document.getElementById('paper-container-h1_dpBandwidth');
    var h2_dpBandwidthBody = document.getElementById('paper-container-h2_dpBandwidth');
    var text = "";
    $.get(url.concat("/ids/h1LpBandwidth"), function(resp){
        var lines = resp.split("\n");
        for (line in lines){
	    if (line<=9)
		continue;
            var new_p = document.createElement('FONT');
            new_p.appendChild(document.createTextNode(lines[line].substring(6)));
//            new_p.innerHTML = lines[line];
            h1_lpBandwidthBody.appendChild(new_p);
            h1_lpBandwidthBody.appendChild(document.createElement('BR'));
        }
    });
    $.get(url.concat("/ids/h2LpBandwidth"), function(resp){
//          idsLogsBody.innerHTML = resp;
        var lines = resp.split("\n");
        for (line in lines){
	    if (line<=9)
		continue;
            var new_p = document.createElement('FONT');
            new_p.appendChild(document.createTextNode(lines[line]));
//            new_p.innerHTML = lines[line];
            h2_lpBandwidthBody.appendChild(new_p);
            h2_lpBandwidthBody.appendChild(document.createElement('BR'));
        }
    });
    $.get(url.concat("/ids/h1DpBandwidth"), function(resp){
        var lines = resp.split("\n");
        for (line in lines){
	    if (line<=9)
		continue;
            var new_p = document.createElement('FONT');
            new_p.appendChild(document.createTextNode(lines[line]));
//            new_p.innerHTML = lines[line];
            h1_dpBandwidthBody.appendChild(new_p);
            h1_dpBandwidthBody.appendChild(document.createElement('BR'));
        }
    });
    $.get(url.concat("/ids/h2DpBandwidth"), function(resp){
//          idsLogsBody.innerHTML = resp;
        var lines = resp.split("\n");
        for (line in lines){
	    if (line<=9)
		continue;
            var new_p = document.createElement('FONT');
            new_p.appendChild(document.createTextNode(lines[line]));
//            new_p.innerHTML = lines[line];
            h2_dpBandwidthBody.appendChild(new_p);
            h2_dpBandwidthBody.appendChild(document.createElement('BR'));
        }
    });
    
}

bandwidthTest();

//var idsRulesIntervalID = setInterval(function(){updateIDSRules()}, 5000);

//function stopIDSRulesRefresh() {
//    clearInterval(idsRulesIntervalID);
//}

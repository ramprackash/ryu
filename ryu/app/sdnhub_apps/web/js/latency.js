var url = "http://" + location.hostname + ":8080";

function latencyTest() {
    var lpLatencyBody = document.getElementById('paper-container-lpLatency');
    var dpLatencyBody = document.getElementById('paper-container-dpLatency');
    var text = "";
    $.get(url.concat("/ids/lpLatency"), function(resp){
        var lines = resp.split("\n");
	var i = 0;
        for (line in lines){
	    if (++i==1)
		continue;
            var new_p = document.createElement('FONT');
            new_p.appendChild(document.createTextNode(lines[line]));
//            new_p.innerHTML = lines[line];
            lpLatencyBody.appendChild(new_p);
            lpLatencyBody.appendChild(document.createElement('BR'));
        }
    });
    $.get(url.concat("/ids/dpLatency"), function(resp){
//          idsLogsBody.innerHTML = resp;
        var lines = resp.split("\n");
	var i=0;
        for (line in lines){
	    if (++i==1)
		continue;
            var new_p = document.createElement('FONT');
            new_p.appendChild(document.createTextNode(lines[line]));
//            new_p.innerHTML = lines[line];
            dpLatencyBody.appendChild(new_p);
            dpLatencyBody.appendChild(document.createElement('BR'));
        }
    });

    
}

latencyTest();

//var idsRulesIntervalID = setInterval(function(){updateIDSRules()}, 5000);

//function stopIDSRulesRefresh() {
//    clearInterval(idsRulesIntervalID);
//}

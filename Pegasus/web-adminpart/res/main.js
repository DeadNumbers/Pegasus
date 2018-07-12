/* main.js */

var last_tick = Date.now();   // local ts last dynamic update was performed
var dynupd_on = 1;  	// dynamic updates switch
var last_ts = 0;		// last server ts, to query only data, updated after this ts
var current_module = 'm_machines';	// id of a current module, to be used in ajax data update query

// stop dynupdate and create error modal
function ErrLabel(header, text)
{
	dynupd_on = 0;
	new Messi(text, {title: header, modal: true});
}

// shows an overlay popup in lower left corner using PNotify
function show_popup(p_title, p_text, p_type, b_autohide = true)
{  var opts = {
  	title: p_title,
  	text: p_text,
  	addclass: "stack-bottomleft",
  	type: p_type,
  	styling: 'jqueryui',
  	min_height: '100px',
  	min_width: '100px',
  	delay: 5000,
  	hide: b_autohide
  };

  new PNotify(opts);
}


// update div with last dynupd stamp
function dynupd_last_ticker()
{
 // update vp_last div
 if (dynupd_on==1) {
 	$("#du_last").html('Online ('+Math.round((Date.now()-last_tick)/1000)+')');
 } else {
 	$("#du_last").html('Offline');
 }
}

// updates count of items in menu line
// 0..3 index matches menu a href order
function update_menu_itemcounts(counts_arr)
{ 	if (counts_arr[0]>0) { $('#b_machines').html(counts_arr[0]); } else { $('#b_machines').empty(); }
 	if (counts_arr[1]>0) { $('#b_creds').html(counts_arr[1]);    } else { $('#b_creds').empty(); }
 	if (counts_arr[2]>0) { $('#b_jobs').html(counts_arr[2]);     } else { $('#b_jobs').empty(); }
 	if (counts_arr[3]>0) { $('#b_sqlog').html(counts_arr[3]);    } else { $('#b_sqlog').empty(); }
 	if (counts_arr[4]>0) { $('#b_taccs').html(counts_arr[4]);    } else { $('#b_taccs').empty(); }
 	if (counts_arr[5]>0) { $('#b_trans').html(counts_arr[5]+' | '+counts_arr[6]);    } else { $('#b_trans').empty(); }
}

// issued for addjob a href click
function addjob_click_handler(caller, event)
{	//console.log('addjob id='+caller.parentNode.parentNode.id);
	var row_id = caller.parentNode.parentNode.id;

	// hide original button
	var $add_button = $(caller);
	$add_button.addClass('hidden');

	// add new select just after hidden
	var $newSelectBox = $(document.createElement('select')).attr('id', caller.parentNode.parentNode.id).append('<option value="">add cmd...</option>');

	$newSelectBox.insertAfter($(caller))
		 .click(function(e) {
			// get selected value
			var selval = $(this).val();

			if ((selval == '')&&($(this).text() == 'add cmd...')) {
				// nothing selected, load items list
				var $select = $(this);
				$select.html('<option value="">Loading...</option>');

                $.post("ajax.php", {m:'q_jlist'},

					function (data) {

						if (typeof data.r !== 'undefined') {
							// fill values
							var html = '<option value="">--select--</option>';
							for (var key in data.r) {
						        html += '<option value="'+data.r[key].id+'">'+data.r[key].v+'</option>';
							} // foreach

							$select.html(html);

						} else { $select.html('<option value="">ERR: load failed</option>'); }

					}, // data callback
					'json'
				); // $.post

			}   // selval == ''

		 })	// on click handler
		 .change(function(e) {
		    // get selected value
			var selval = $(this).val();

			if (selval != '') {

				// something selected, issue add query with handler to show notification
				$.post("ajax.php", {m:'q_addjob', t:row_id, j:selval},

						function (data) {

							// show popup notification according to results
							show_popup(data.c, data.t, data.p);


						},
				'json'
				); // $.post

				// and destroy select, restoring original button
				$(this).remove();
				$add_button.removeClass('hidden');

			} // selval != ''

		 });	// on change handler


	//$(caller).after('<select><option value="">add job...</option></select>').onclick


	return;
}

// default cmd handler
function default_cmd_click_handler(caller, event)
{

		var bModuleCheck = false;

		// prepare params, check for special cmd a hrefs, to prepare another params
		switch (caller.id) {			case 'del-ljob': 	var params = {m:caller.id, r:caller.parentNode.parentNode.id}; break;
			default: 			bModuleCheck = true; var params = {m:current_module, c:caller.id, r:caller.parentNode.parentNode.id}; break;
		}
       	// query cmd to server
       	$.post("ajax.php", params,

			function (data) {

				// check for server error
				if (typeof data.error !== 'undefined') { ErrLabel('Server reports problem', data.error); return; }

                // check if module is still the same
                if ((bModuleCheck === true) && (data.m != current_module)) { return; }

				// check for simple cmd answer which instructs to modify DOM
       			if (typeof data.res !== 'undefined') {

					if (typeof data.r !== 'undefined') { $targ_row = $('#'+data.r); }

					switch (data.res) {

						case 'delrow': $targ_row.replaceWith(); break;
						case 'upd': dynupd_do(false); break;

						default: ErrLabel('Server answer error', 'Unknown server DOM cmd ['+data.res+']');

					} // switch

       			} // have DOM modification result

			},
			'json'
		); // $.post

}

// query full info about commands assigned to specific client
function jobinfo_click_handler(caller, event)
{

	// assign static values to dialog, including id of row to be queried
	$mid_div = $('#ljd-mid');
	$mid_div.html('...');
	$mid_div.removeAttr('class');
	$mid_div.addClass(caller.parentNode.parentNode.id);

	$('#jd_table').find('tbody').replaceWith('<tbody><tr><td  colspan="7">Loading...</td></tr></tbody>');
	// show modal dialog form to display info
	window['jl_dialog'].dialog("open");

	// ajax data query is done by dialog's callback


}


// assigns a table onclick handle to handle clicks on td
function assign_table_cmd_handler($table_div)
{ 	$table_div.on('click', 'a', function(event) {

		// check for addcmd class to call specific handler
		switch(this.className) {
			case 'addjob': addjob_click_handler(this, event); break;
			case 'j_info': jobinfo_click_handler(this, event); break;
            case 'cmd': default_cmd_click_handler(this, event); break;
            default: console.log('unk cmd '+this.className); break;
		} // switch

        event.stopImmediatePropagation();
		return false;

 	});	// td onclick handler

}

// displays table header according to current current_module value
function RedrawTableHeader()
{
 var html = ''; switch(current_module) {
 	case 'm_machines' : html = '<table class="table table-striped table-hover " id="m_table">\
								  <thead>\
								    <tr>\
								      <th>#</th>\
								      <th>MID<br>IP, City</th>\
								      <th>Creds scan</th>\
								      <th>Machine<br>Domain</th>\
								      <th>Memo</th>\
								      <th>Arch<br>Build id</th>\
								      <th>Last seen (ago)<br>Local time</th>\
								      <th>Uptime (49d limit)<br>Cmds (pending/done)</th>\
								      <th>Timezone</th>\
								      <th>Controls</th>\
								    </tr>\
								  </thead>\
								  <tbody>\
                                   \
								  </tbody>\
								</table>'; break;

	case 'm_creds' : html = '<table class="table table-striped table-hover " id="m_table">\
								  <thead>\
								    <tr>\
								      <th>#</th>\
								      <th>Stamp (ago)</th>\
								      <th>Source machine</th>\
								      <th>Domain\\User:Pass</th>\
								    </tr>\
								  </thead>\
								  <tbody>\
                                   \
								  </tbody>\
								</table>'; break;

 	case 'm_sqlog' : html = '<table class="table table-striped table-hover " id="m_table">\
								  <thead>\
								    <tr>\
								      <th>#</th>\
								      <th>Stamp (ago)</th>\
								      <th>Source</th>\
								      <th>Log</th>\
								      <th>Controls</th>\
								    </tr>\
								  </thead>\
								  <tbody>\
                                   \
								  </tbody>\
								</table>'; break;

	 case 'm_jobs' : html = '<table class="table table-striped table-hover " id="m_table">\
								  <thead>\
								    <tr>\
								      <th>#</th>\
								      <th>Created</th>\
								      <th>Memo</th>\
								      <th>Assignment</th>\
								      <th>Target arch</th>\
								      <th>Contents</th>\
								      <th>Controls</th>\
								    </tr>\
								  </thead>\
								  <tbody>\
                                   \
								  </tbody>\
								  <tfoot><tr><td colspan="7"><button id="add-job">Add new</button></td></tr></tfoot>\
								</table>'; break;

		 case 'm_taccs' : html = '<table class="table table-striped table-hover " id="m_table">\
								  <thead>\
								    <tr>\
								      <th>#</th>\
								      <th>Last upd</th>\
								      <th>Memo</th>\
								      <th>Status</th>\
								      <th>Limits range<br>Count | Sum</th>\
								      <th>Registered</th>\
								      <th>Params</th>\
								      <th>Controls</th>\
								    </tr>\
								  </thead>\
								  <tbody>\
                                   \
								  </tbody>\
								  <tfoot><tr><td colspan="8"><button id="add-tacc">Add new</button></td></tr></tfoot>\
								</table>'; break;

  	default: html = 'no module data'; break;

 } // switch

	$table_div = $("#table_div");

 	$table_div.html(html);
 	last_ts = 0;	// to query new data

 	// assign click on td handler for cmd implementation
 	assign_table_cmd_handler($table_div);

 	// assign add new job button handler
 	$('#add-job').button().on( "click", function() {
 				// trigger event to display correct contents
				$('#newjob-type-select').change();
				$('#newjob-asg-select').val(0);
				$('#newjob-asg-select').change();
				// show dialog
				window['ag_dialog'].dialog( "open" );
			});

	// assign add new tacc button handler
    $('#add-tacc').button().on( "click", function() { $('#newtacc-form').trigger('reset'); window['ta_dialog'].dialog( "open" ); });
}

function htmlEncode(value){
  //create a in-memory div, set it's inner text(which jQuery automatically encodes)
  //then grab the encoded contents back out.  The div never exists on the page.
  return $('<div/>').text(value).html();
}

// serializes log json object into text/table representation
function serialize_log(log)
{
	var res = '';
	for (var key in log) {        var val = log[key];
        res += htmlEncode(key)+" : "+htmlEncode(val)+"<br>";
	} // foreach

	return res;
}


// returns a single table row formatted for a specific module
function FormHtmlRow(module_name, di, row_class='')
{ switch(module_name) {

 	case 'm_machines' : if (di.vmemo == '') { di.vmemo = '&nbsp;'; }

 						return "<tr id='"+di.id+"' class='"+row_class+"'>\
							<td>"+di.id+"</td>\
							<td>"+di.mid+"<br>"+di.ipc+"</td>\
							<td>"+di.cs+"</td>\
							<td>"+di.m_name+"<br>"+di.d_name+"</td>\
							<td class='jedit' id='b"+di.id+"'>"+di.memo+"</td>\
							<td>"+di.arch+"<br>id"+di.blid+" <span class='jedit' id='l"+di.blid+"'>"+di.vmemo+"</span></td>\
							<td>"+di.stamp+" ("+di.ts_ago+")<br>"+di.l_ft+"</td>\
							<td>"+di.l_ticks+"<br><a href='#' class='j_info'>"+di.cst+"</a></td>\
							<td>"+di.tz+"</td>\
							<td><a href='#' class='addjob'>add cmd</a><br></td>\
							</tr>";

	case 'm_creds' : return "<tr id='"+di.id+"' class='"+row_class+"'>\
							<td>"+di.id+"</td>\
							<td>"+di.stamp+" ("+di.ts_ago+")</td>\
							<td>"+di.SM+"</td>\
							<td>"+di.cred+"</td>\
							</tr>";

 	case 'm_sqlog' :  return "<tr id='"+di.id+"' class='"+row_class+"'>\
							<td>"+di.id+"</td>\
							<td>"+di.stamp+" ("+di.ts_ago+")</td>\
							<td>"+di.log['Remote-Address']+"</td>\
							<td>"+serialize_log(di.log)+"</td>\
							<td><a href='#' class='cmd' id='remove'>remove</a></td>\
							</tr>";

	case 'm_jobs' : return "<tr id='"+di.id+"' class='"+row_class+"'>\
							<td>"+di.id+"</td>\
							<td>"+di.stamp+"</td>\
							<td class='jedit' id='"+di.id+"'>"+di.memo+"</td>\
							<td>"+di.auto+"</td>\
							<td>"+di.targ_arch+"</td>\
							<td>"+di.contents+"</td>\
							<td><a href='#' class='cmd' id='del-job'>remove</a></td>\
							</tr>";

	case 'm_taccs' : return	"<tr id='"+di.id+"' class='"+row_class+"'>\
							<td>"+di.id+"</td>\
							<td>"+di.stamp+" ("+di.ts_ago+")</td>\
							<td class='jedit' id='"+di.id+"'>"+di.memo+"</td>\
							<td><a href='#' class='cmd' id='switch-ta'>"+di.status+"</a></td>\
							<td>"+di.limits+"</td>\
							<td>"+di.reginfo+"</td>\
							<td>"+di.params+"</td>\
							<td><a href='#' class='cmd' id='del-ta'>remove</a></td>\
							</tr>";

	case 'q_jlist_cid' :    var answ_row = '';
							if ((typeof di.answer !== 'undefined') && (di.answer.length > 0)) {
							answ_row = "</tr>\
							<tr id='ja"+di.id+"' class='"+row_class+"'>\
							<td colspan='7'><pre>"+di.answer+"</pre></td>\
							</tr>"; }
							return "<tr id='j"+di.id+"' class='"+row_class+"'>\
							<td>"+di.id+"</td>\
							<td>"+di.as+"</td>\
							<td>"+di.ls+"</td>\
							<td>"+di.v+"</td>\
							<td>"+di.status+"</td>\
							<td></td>\
							<td><a href='#' class='cmd' id='del-ljob'>remove</a></td>"+answ_row;

    // 0 - build id, 1 - amount, 2 - memo
	case 'q_bids': return "<li><a href='#' id='bi"+di[0]+"'>"+di[2]+" (id "+di[0]+") <span class='badge'>"+di[1]+"</span></a></li>";

 } // switch

}


// re-assigns jeditable component to all new/existing items
function reassign_jedit()
{ 	$('.jedit').editable('ajax.php',{ 		placeholder : '',
 		id : 'jeid',
 		submitdata : {m: current_module}
 	});

}


// called periodically to perform update of interface
// do_recall passed as false when re-creating table on menu navigation
function dynupd_do(do_recall = true)
{
	// issue ajax query	$.post("ajax.php", {m:current_module, ts:last_ts},

		function (data) {

			// check for server error
			if (typeof data.error !== 'undefined') { ErrLabel('Server reports problem', data.error); return; }

			// check for json parse error
			if ((typeof data.r === 'undefined') || (typeof data.c === 'undefined')) { ErrLabel('Query error', 'Invalid answer from server'); return; }

			// check for correct current module
			if (data.m != current_module) { return; }

			var add_html_rows = [];    // html text to be appended

			// cycle items received
			for (var i in data.r) {
				// form resulting html code
				row_html = FormHtmlRow(current_module, data.r[i], 'newrow');

				// try to find existing row
				var $targ_row = $('#'+data.r[i].id);
				if (!$targ_row.length) {					// add new record
					//$('#m_table').find('tbody:first').append(row_html);
					add_html_rows.push(row_html);
				} else {
					// modify existing row					$targ_row.replaceWith(row_html);

					// add highlight on changed row - replaced, need to search again
					$('#'+data.r[i].id).effect("highlight", {color: '#aaeeaa'}, 4000);
				}



			} // for

			// add new rows, if any
			if (add_html_rows.length) {
				$('#m_table').find('tbody:first').append(add_html_rows);

				// add effect if not first query
				var $new_rows = $('.newrow');
				if (last_ts>0) { $new_rows.effect("highlight", {color: '#aaeeaa'}, 4000);  }
				$new_rows.removeClass('newrow');

			}

			// check q-log count
			if ((typeof data.mc[3] !== 'undefined') && (data.mc[3] > 0)) {

				// check if not shown already
				if (window['qc_warn_shown'] !== true) {

					//$('#warn_text').html(data.qc+' records in suspicious query log, please review it ASAP');
					//$('#alert_div').removeClass('hidden');

					window['qc_warn_shown'] = true;
					show_popup('Warning', data.mc[3]+' records in suspicious query log, please review it ASAP', 'info', false);

				} // not shown before
			}

			// update items count nearby menu line
			update_menu_itemcounts(data.mc);

			// after all done, renew ts
			last_tick = Date.now();
			if (data.ts) { last_ts = data.ts; }

			// self-recall, if still turned on
            if ( (dynupd_on==1)&&(do_recall) ) { setTimeout( dynupd_do, 3000); }

			reassign_jedit();

		}, // data callback
       'json'
	);	// $.post

}

// called to prepare and send form newjob-form
function addJob()
{
	// check if form is being uploaded
	if ($('#addjob-dialog-form').hasClass('inprogress') ) { return false; }
	$('#addjob-dialog-form').addClass('inprogress');

	// basic checks
	$form = $('#newjob-form');
	if ($form.find('input[name=memo]').val() == '') {
		ErrLabel('Fill memo', 'Need to fill memo field');
		$('#addjob-dialog-form').removeClass('inprogress');
		return false;
	}

	// if file uploads exists, hide file selection and place progress indicator
	if ($('#upf').length) {
		$('#upf').addClass("hidden");
		$('#newjob-contents-div').append('<div class="progress">\
  <div class="progress-bar progress-bar-striped active" role="progressbar"\
  id="pb" style="width:0%">\
    0%\
  </div>\
</div>');
	}   // if upload file field present





	// do ajax form send

    $form.ajaxSubmit({    data: { m: 'm_jobs', cmd: 'addjob' },
    type: 'POST',
    dataType: 'json',    beforeSend: function() {
        //status.empty();
        var percentVal = '0%';
        $('#pb').width(percentVal)
				.text(percentVal);
    },
    uploadProgress: function(event, position, total, percentComplete) {
        var percentVal = percentComplete + '%';
        $('#pb').width(percentVal)
	        	.text(percentVal);
        //console.log('done '+percentVal);
    },
	success: function(res) {
		$('#addjob-dialog-form').removeClass('inprogress');
		window['ag_dialog'].dialog( "close" );
		// check if server reported any error
		if (typeof res.error !== 'undefined') { ErrLabel('Add job failed, server reports error', res.error); }

	},
	error: function() {		$('#addjob-dialog-form').removeClass('inprogress');
		window['ag_dialog'].dialog( "close" );
		ErrLabel('Upload error', 'Form upload to remote server failed');
	}

    });

	//console.log('add job');
}



// called to prepare and send form newtacc-form (check fields, issue query)
function addTAcc()
{

	$form = $('#newtacc-form');
	// do ajax form send
    $form.ajaxSubmit({
    data: { m: 'm_taccs', cmd: 'addtacc' },
    type: 'POST',
    dataType: 'json',
	success: function(res) {
		//window['ta_dialog'].dialog( "close" );
		// check if server reported any error
		if (typeof res.error !== 'undefined') { ErrLabel('Add failed, server reports error', res.error); } else {

			// uploaded ok, clear volatile form fields
	        $('#addtacc-dialog-form .volatile').val('');

        }
	}

    });

   //window['ta_dialog'].dialog( "close" );
}


$(document).ready(function()
{

	// error handler
	$( document ).ajaxError(function( event, jqxhr, settings, thrownError ) {
		ErrLabel('Ajax query error', settings.url+'<br><br>'+thrownError+'<br><br>Online updates will be turned off');
		dynupd_on = 0;
	});

	// before send handler to be able to cancel all pending requests
	$.xhrPool = [];
	$.xhrPool.abortAll = function () {		$(this).each( function(idx, jqXHR){ jqXHR.abort(); } );
	    //$.xhrPool = [];
	};

	$.ajaxSetup({    	beforeSend: function(jqXHR) { $.xhrPool.push(jqXHR); },
    	complete: function(jqXHR) {    		      	var ind = $.xhrPool.indexOf(jqXHR);
    		      	if (ind > -1) { $.xhrPool.splice(ind, 1); }
    			  }

	});

	// table header
	RedrawTableHeader();
	// dynupdate
 	setInterval( dynupd_last_ticker, 500);
 	setTimeout( dynupd_do, 1000);
    $("#du_last").click(function(e){
     	dynupd_on = !dynupd_on;
		if (dynupd_on==1) { $("#du_last").html('Online'); setTimeout( dynupd_do, 1000); } else { $("#du_last").html('Offline'); }
    });

    // navbar menu handler
    $("#menu li a").click(function(event){

		// switch classes
  		$("#menu li").removeClass('active');
        this.parentElement.className = 'active';
    	//alert("Hello! "+this.id);

		// check if module changed
		if (current_module == this.id) { return; }

		// cancel all pending ajax queries (auto update, form posts, etc)
		$.xhrPool.abortAll();

    	// set global id
    	current_module = this.id;

    	// redraw table header
    	RedrawTableHeader();

    	// force update with recall of updater
    	dynupd_do(false);

		return false;	// no default & prop

	}) // navbar menu handler


	// add job modal
	 var $dialog = $('#addjob-dialog-form').dialog({
		autoOpen: false,
		width: 550,
		modal: true,
		buttons: {
			"Add new job": addJob,
			Cancel: function() { if (!$('#addjob-dialog-form').hasClass('inprogress')) { $dialog.dialog( "close" ); } }
		},
		close: function() { $('#newjob-form').trigger('reset'); }
		});  // dialog

	$dialog.find("form").on( "submit", function( event ) {
		event.preventDefault();
		addJob();
	});
	window['ag_dialog'] = $dialog;


	// add taccs modal
	var $dialog = $('#addtacc-dialog-form').dialog({
		autoOpen: false,
		width: 550,
		modal: true,
		buttons: {
			"Add new": addTAcc,
			Cancel: function() { if (!$('#addtacc-dialog-form').hasClass('inprogress')) { $dialog.dialog( "close" ); } }
		},
		close: function() { $('#newtacc-form').trigger('reset'); }
		});  // dialog

	$dialog.find("form").on( "submit", function( event ) {
		event.preventDefault();
		addTAcc();
	});
	window['ta_dialog'] = $dialog;

    // jobs list modal
    var $lj_dialog = $('#listjobs-dialog').dialog({        autoOpen: false,
		modal: true,
		width: 1100,
		open: function() {

			$dialog_div = $('#listjobs-dialog');
			$mid_div = $('#ljd-mid');

			//$mid_div.html('...');
			// prevent close while query data
			$dialog_div.addClass('inprogress');

				//console.log('on open '+$mid_div.attr('class'));
                $.post("ajax.php", {m:'q_jlist_cid', id:$mid_div.attr('class')},

					function (data) {

						var html = '';

						// prepare resulting rows html
						for (var i in data.r) {

							// form resulting html code
							html += FormHtmlRow('q_jlist_cid', data.r[i]);

                        } // for

                        // default empty row, if nothing in answer
                        if (data.r.length == 0) { html = '<tr><td colspan="7">No records</td></tr>'; }

						// assign to table
						$('#jd_table').find('tbody').replaceWith('<tbody>'+html+'</tbody>');

						// mid
						$mid_div.html(data.mid);

					}, // data callback
			       'json'
				);	// $.post

			// allow close
			$dialog_div.removeClass('inprogress');

		}, // open
		buttons: {
			"Close": function() { if (!$('#listjobs-dialog').hasClass('inprogress')) { $lj_dialog.dialog( "close" ); } }
		}

    }); // dialog
    window['jl_dialog'] = $lj_dialog;

    // assign handler on jobs list invisible dialog
    assign_table_cmd_handler($('#jd_table'));


	// newjob-type-select onchange handler to put a correct element into
	$('#newjob-type-select').change(function(e){		var html = '';
		switch ($('#newjob-type-select').val()) {
			// shell script
			case '1' : html = '<textarea name="shs" rows=8 cols=68 wrap="off"></textarea>'; break;
            case '2' :
            case '3' :
            case '4' : html = '<input name="upf" id="upf" type="file" value="" size="1">'; break;
            case '5' : html = '<i>no configurable params</i>'; break;
			default : html = '<i>Unknown type '+$('#newjob-type-select').val()+'</i>'; break;
		} // switch
		$('#newjob-contents-div').html(html);
	});

	// newjob-assignment-type onchange handler to show and hide extra checkbox (at add_to_existing div)
	$('#newjob-asg-select').change(function(e) {
		switch ($('#newjob-asg-select').val()) {

			case '0': $('#add_to_existing').addClass('hidden'); break;
			case '1': $('#add_to_existing').removeClass('hidden'); break;

		} // switch
	});


	// addtacc-dialog-form interactive form type switch
	$('.tacc-frm-switch').click(function(event) {
		var $st_inp = $('#newtacc-form').find('input[name=s_btype]');

		var state = $st_inp.val();
		if (state == 1) { state = 2; } else { state = 1; }
        $st_inp.val(state);
		//console.log('newstate='+state);

        switch (state) {
        	case 1: $('#manual_add').addClass('hidden'); $('#bulk_add').removeClass('hidden'); break;
        	case 2: $('#manual_add').removeClass('hidden'); $('#bulk_add').addClass('hidden'); break;

        } // switch

	    event.preventDefault();
     	event.stopPropagation();
	});



	// dropdown on show handler to dynamically update items on click
	$('#bi_dropdown').on('show.bs.dropdown', function() {
		var $bi_items = $('#bi_items');
		$bi_items.html('&nbsp;loading...');

		// issue query to get all ids
		 $.post("ajax.php", {m:'q_bids'},
			function (data) {
				// check for special cases
				if (typeof data.bids == 'undefined') { $bi_items.html('&nbsp;query failure: '+data.error); return; }
				if (data.bids.length == 0) { $bi_items.html('&nbsp;No records'); return; }

				// prepare resulting rows html
				var html = '';
				for (var i in data.bids) {  html += FormHtmlRow('q_bids', data.bids[i]); }

				// all items record
				html += "<li><a href='#' id='bi0'>Show All</a></li>";

                $bi_items.html(html);

                // re-assign click callback on entire block
                // ...

			}, 'json');  // post.callback

	}); // on show.bs.dropdown


});



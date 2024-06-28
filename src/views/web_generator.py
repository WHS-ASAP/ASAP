# import pandas as pd
# import os

# def save_findings_as_html(all_findings, output_dir='Analyze_Web', asset_dir='asset'):
#     if not os.path.exists(output_dir):
#         os.makedirs(output_dir)

#     package_count = 1
#     main_links = []

#     for package, findings in all_findings.items():
#         df = pd.DataFrame(findings)
#         html = df.to_html(index=False, escape=False)
#         package_file = f'{output_dir}/package_{package_count}.html'
#         with open(package_file, 'w') as f:
#             f.write(f"""
#             <!DOCTYPE html>
#             <html lang="en">
#             <head>
#                 <meta charset="UTF-8">
#                 <meta name="viewport" content="width=device-width, initial-scale=1.0">
#                 <title>Findings - Package {package_count}</title>
#                 <link rel="stylesheet" href="https://cdn.datatables.net/1.10.21/css/jquery.dataTables.min.css">
#                 <link href="https://fonts.googleapis.com/css2?family=Comic+Neue&display=swap" rel="stylesheet">
#                 <style>
#                     body {{
#                         font-family: 'Comic Neue', sans-serif;
#                         background: -webkit-linear-gradient(left, #25c481, #25b7c4);
#                         background: linear-gradient(to right, #25c481, #25b7c4);
#                         color: #fff;
#                     }}
#                     h1 {{
#                         text-align: center;
#                         font-size: 30px;
#                         text-transform: uppercase;
#                         font-weight: 300;
#                         margin-bottom: 15px;
#                     }}
#                     table{{
#                       width:100%;
#                       height:100%;
#                       table-layout: fixed;
#                     }}
#                     .tbl-header {{
#                         background-color: rgba(255,255,255,0.3);
#                     }}
#                     .tbl-content {{
#                         height: 600px;
#                         overflow-x: auto;
#                         margin-top: 0px;
#                         border: 1px solid rgba(255,255,255,0.3);
#                     }}
#                     th {{
#                         padding: 20px 15px;
#                         text-align: center;
#                         vertical-align: middle;
#                         font-weight: 500;
#                         font-size: 12px;
#                         text-transform: uppercase;
#                         color: #fff;
#                     }}
#                     td {{
#                         padding: 15px;
#                         text-align: center;
#                         vertical-align: middle;
#                         font-weight: 300;
#                         font-size: 12px;
#                         color: #fff;
#                         border-bottom: solid 1px rgba(255,255,255,0.1);
#                     }}
#                     ::-webkit-scrollbar {{
#                         width: 6px;
#                     }}
#                     ::-webkit-scrollbar-track {{
#                         -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,0.3);
#                     }}
#                     ::-webkit-scrollbar-thumb {{
#                         -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,0.3);
#                     }}
#                     .made-with-love {{
#                         margin-top: 40px;
#                         padding: 10px;
#                         clear: left;
#                         text-align: center;
#                         font-size: 10px;
#                         font-family: arial;
#                         color: #fff;
#                     }}
#                     .made-with-love i {{
#                         font-style: normal;
#                         color: #F50057;
#                         font-size: 14px;
#                         position: relative;
#                         top: 2px;
#                     }}
#                     .made-with-love a {{
#                         color: #fff;
#                         text-decoration: none;
#                     }}
#                     .made-with-love a:hover {{
#                         text-decoration: underline;
#                     }}
#                 </style>
#                 <script src="https://code.jquery.com/jquery-3.5.1.js"></script>
#                 <script src="https://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js"></script>
#                 <script>
#                     $(document).ready(function() {{
#                         $('#findings').DataTable({{
#                             "paging": true,
#                             "pageLength": 10,
#                             "lengthChange": false,
#                             "searching": true,
#                             "ordering": true,
#                             "info": true,
#                             "autoWidth": false
#                         }});
#                         var scrollWidth = $('.tbl-content').width() - $('.tbl-content table').width();
#                         $('.tbl-header').css({{'padding-right': scrollWidth}});
#                     }});
#                 </script>
#             </head>
#             <body>
#                 <h1>Result of {package}</h1>
#                 <div class="tbl-header">
#                     <table cellpadding="0" cellspacing="0" border="0">
#                         <thead>
#                             {html.split('<thead>')[1].split('</thead>')[0]}
#                         </thead>
#                     </table>
#                 </div>
#                 <div class="tbl-content">
#                     <table cellpadding="0" cellspacing="0" border="0">
#                         <tbody>
#                             {html.split('<tbody>')[1].split('</tbody>')[0]}
#                         </tbody>
#                     </table>
#                 </div>
#             </body>
#             </html>
#             """)
#         main_links.append(f'<li><a href="package_{package_count}.html">Package {package_count}: {package}</a></li>')
#         package_count += 1

#     with open(f'{output_dir}/list.html', 'w') as f:
#         f.write(f"""
#         <!DOCTYPE html>
#         <html lang="en">
#         <head>
#             <meta charset="UTF-8">
#             <meta name="viewport" content="width=device-width, initial-scale=1.0">
#             <title>Package List</title>
#             <link href="https://fonts.googleapis.com/css2?family=Comic+Neue&display=swap" rel="stylesheet">
#             <style>
#                 body {{
#                     font-family: 'Comic Neue', sans-serif;
#                     text-align: center;
#                 }}
#                 h1 {{
#                     text-align: center;
#                     font-size: 40px;
#                     color: #A4C639; /* Android 연두색 */
#                 }}
#                 ul {{
#                     list-style-type: none;
#                     padding: 0;
#                 }}
#                 li {{
#                     margin: 5px 0;
#                 }}
#                 a {{
#                     color: #A4C639; /* Android 연두색 */
#                     text-decoration: none;
#                     font-size: 20px;
#                 }}
#                 a:hover {{
#                     color: #7A9E38; /* 어두운 연두색 */
#                 }}
#             </style>
#         </head>
#         <body>
#             <h1>Package List</h1>
#             <ul>
#                 {''.join(main_links)}
#             </ul>
#         </body>
#         </html>
#         """)

#     with open(f'{output_dir}/main.html', 'w') as f:
#         f.write(f"""
#         <!DOCTYPE html>
#         <html lang="en">
#         <head>
#             <meta charset="UTF-8">
#             <meta name="viewport" content="width=device-width, initial-scale=1.0">
#             <title>Main Page</title>
#             <link href="https://fonts.googleapis.com/css2?family=Comic+Neue&display=swap" rel="stylesheet">
#             <style>
#                 body {{
#                     font-family: 'Comic Neue', sans-serif;
#                     text-align: center;
#                     background-image: url('../{asset_dir}/android.png');
#                     background-size: cover;
#                     background-repeat: no-repeat;
#                     background-attachment: fixed;
#                     color: white;
#                 }}
#                 h1 {{
#                     font-size: 50px;
#                     margin-top: 20%;
#                 }}
#                 a {{
#                     color: white;
#                     text-decoration: none;
#                     font-size: 20px;
#                 }}
#                 a:hover {{
#                     color: #D3D3D3; /* 밝은 회색 */
#                 }}
#             </style>
#         </head>
#         <body>
#             <h1>ASAP</h1>
#             <a href="list.html">View Analysis Results</a>
#         </body>
#         </html>
#         """)
import os

def save_findings_as_html(all_findings, output_dir='Analyze_Web', asset_dir='asset'):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    package_count = 1
    main_links = []

    def get_badge(issue):
        if 'SQLInjection' in issue:
            return '<span class="badge-red">SQL Injection</span>'
        elif 'HardCoded' in issue:
            return '<span class="badge-orange">Hardcoded Value</span>'
        elif 'WebView' in issue:
            return '<span class="badge-yellow">WebView Vulnerability</span>'
        elif 'Permission' in issue:
            return '<span class="badge-green">Permission Issue</span>'
        elif 'DeepLink' in issue:
            return '<span class="badge-blue">DeepLink Issue</span>'
        else:
            return '<span class="badge-purple">Unknown Issue</span>'

    for package, findings in all_findings.items():
        headers = findings[0].keys()
        thead = "<thead><tr>" + "".join(f"<th>{header}</th>" for header in headers) + "</tr></thead>"
        tbody = "<tbody>" + "".join(
            "<tr>" + "".join(f"<td>{get_badge(finding[key])}</td>" if key == 'Issue' else f"<td>{finding[key]}</td>" for key in headers) + "</tr>" for finding in findings
        ) + "</tbody>"

        package_file = f'{output_dir}/package_{package_count}.html'
        with open(package_file, 'w') as f:
            f.write(f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Findings - Package {package_count}</title>
                <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
                <link href="https://fonts.googleapis.com/css2?family=Comic+Neue&display=swap" rel="stylesheet">
                <style>
                    body {{
                        font-family: 'Comic Neue', sans-serif;
                    }}
                    h4 {{
                        text-align: center;
                        font-size: 30px;
                        text-transform: uppercase;
                        font-weight: 300;
                        margin-bottom: 15px;
                    }}
                    .badge-red {{
                        background-color: #FF0000;
                        color: white;
                        padding: 0.5em 0.75em;
                        font-size: 90%;
                        border-radius: 5px;
                    }}
                    .badge-orange {{
                        background-color: #FFA500;
                        color: white;
                        padding: 0.5em 0.75em;
                        font-size: 90%;
                        border-radius: 5px;
                    }}
                    .badge-yellow {{
                        background-color: #FFFF00;
                        color: black;
                        padding: 0.5em 0.75em;
                        font-size: 90%;
                        border-radius: 5px;
                    }}
                    .badge-green {{
                        background-color: #008000;
                        color: white;
                        padding: 0.5em 0.75em;
                        font-size: 90%;
                        border-radius: 5px;
                    }}
                    .badge-blue {{
                        background-color: #0000FF;
                        color: white;
                        padding: 0.5em 0.75em;
                        font-size: 90%;
                        border-radius: 5px;
                    }}
                    .badge-purple {{
                        background-color: #800080;
                        color: white;
                        padding: 0.5em 0.75em;
                        font-size: 90%;
                        border-radius: 5px;
                    }}
                    .badge-indigo {{
                        background-color: #4B0082;
                        color: white;
                        padding: 0.5em 0.75em;
                        font-size: 90%;
                        border-radius: 5px;
                    }}
                    .table-wrapper {{
                        display: block;
                        max-width: 100%;
                        overflow-x: auto;
                        white-space: nowrap;
                        -webkit-overflow-scrolling: touch;
                    }}
                    .table thead th {{
                        border-bottom: 2px solid #dee2e6;
                    }}
                    .table tbody td {{
                        border-top: 1px solid #dee2e6;
                    }}
                    .table-bordered {{
                        border: 1px solid #dee2e6;
                    }}
                    .table-bordered th, .table-bordered td {{
                        border: 1px solid #dee2e6;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="row">
                        <div class="col-lg-12 grid-margin stretch-card">
                            <div class="card">
                                <div class="card-body">
                                    <h4 class="card-title">Findings - {package}</h4>
                                    <div class="table-wrapper">
                                        <table class="table table-bordered">
                                            {thead}
                                            {tbody}
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
                <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"></script>
            </body>
            </html>
            """)

        main_links.append(f'<li><a href="package_{package_count}.html">Package {package_count}: {package}</a></li>')
        package_count += 1

    with open(f'{output_dir}/list.html', 'w') as f:
        f.write(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Package List</title>
            <link href="https://fonts.googleapis.com/css2?family=Comic+Neue&display=swap" rel="stylesheet">
            <style>
                body {{
                    font-family: 'Comic Neue', sans-serif;
                    text-align: center;
                }}
                h1 {{
                    text-align: center;
                    font-size: 40px;
                    color: #A4C639;
                }}
                ul {{
                    list-style-type: none;
                    padding: 0;
                }}
                li {{
                    margin: 5px 0;
                }}
                a {{
                    color: #A4C639;
                    text-decoration: none;
                    font-size: 20px;
                }}
                a:hover {{
                    color: #7A9E38;
                }}
            </style>
        </head>
        <body>
            <h1>Package List</h1>
            <ul>
                {''.join(main_links)}
            </ul>
        </body>
        </html>
        """)

    with open(f'{output_dir}/main.html', 'w') as f:
        f.write(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Main Page</title>
            <link href="https://fonts.googleapis.com/css2?family=Comic+Neue&display=swap" rel="stylesheet">
            <style>
                body {{
                    font-family: 'Comic Neue', sans-serif;
                    text-align: center;
                    background-image: url('../{asset_dir}/android.png');
                    background-size: cover;
                    background-repeat: no-repeat;
                    background-attachment: fixed;
                    color: white;
                }}
                h1 {{
                    font-size: 50px;
                    margin-top: 20%;
                }}
                a {{
                    color: white;
                    text-decoration: none;
                    font-size: 20px;
                }}
                a:hover {{
                    color: #D3D3D3;
                }}
            </style>
        </head>
        <body>
            <h1>ASAP</h1>
            <a href="list.html">View Analysis Results</a>
        </body>
        </html>
        """)

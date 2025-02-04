/*
 * CODE GENERATED AUTOMATICALLY WITH
 *    github.com/wlbr/templify
 * THIS FILE SHOULD NOT BE EDITED BY HAND
 */

package reporter

// template_reportTemplate is a generated function returning the template as a string.
// That string should be parsed by the functions of the golang's template package.
func template_reportTemplate() string {
	var tmpl = "{{- /*gotype: github.com/afbase/secrets-searcher/pkg/reporter.reportData*/ -}}\n" +
		"<!DOCTYPE html>\n" +
		"<html lang=\"en\">\n" +
		"<head>\n" +
		"    <meta charset=\"UTF-8\">\n" +
		"    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n" +
		"    <title>Search Secrets Report {{.ReportDate.Format \"01/02/2006 15:04:05\"}}</title>\n" +
		"    <link href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css\" rel=\"stylesheet\"\n" +
		"          integrity=\"sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh\" crossorigin=\"anonymous\">\n" +
		"    <link href=\"https://fonts.googleapis.com/icon?family=Material+Icons\" rel=\"stylesheet\">\n" +
		"    {{template \"styles\"}}\n" +
		"</head>\n" +
		"<body>\n" +
		"<div class=\"container-fluid\">\n" +
		"    <h2>Search Secrets Report</h2>\n" +
		"    <table class=\"table report-info\">\n" +
		"        <tr>\n" +
		"            <th scope=\"row\">Secrets found</th>\n" +
		"            <td>{{.SecretCountMsg}}</td>\n" +
		"        </tr>\n" +
		"        <tr>\n" +
		"            <th scope=\"row\">Completed</th>\n" +
		"            <td>{{.ReportDate.Format \"01/02/2006 15:04:05\"}}</td>\n" +
		"        </tr>\n" +
		"        {{if .Secrets}}\n" +
		"            <tr>\n" +
		"                <th scope=\"row\">Repos with secrets</th>\n" +
		"                <td>\n" +
		"                    {{range $index, $repoName := .Repos}}{{if $index}}, {{end}}{{$repoName}}{{end}}\n" +
		"                </td>\n" +
		"            </tr>\n" +
		"        {{end}}\n" +
		"    </table>\n" +
		"\n" +
		"    {{if not .Secrets}}\n" +
		"        <div class=\"container-fluid\">\n" +
		"            <div class=\"row\">\n" +
		"                <div class=\"col\">\n" +
		"                    No secrets were found.\n" +
		"                </div>\n" +
		"            </div>\n" +
		"        </div>\n" +
		"    {{else}}\n" +
		"        <div class=\"container-fluid\">\n" +
		"            <p>\n" +
		"                <a href=\"javascript:\" class=\"expand-all\">Expand all</a> /\n" +
		"                <a href=\"javascript:\" class=\"collapse-all\">Collapse all</a>\n" +
		"            </p>\n" +
		"            {{$defaultGroup:=.DefaultGroup}}\n" +
		"            {{range $groupName, $secrets := .Secrets}}\n" +
		"\n" +
		"                {{if eq $groupName $defaultGroup }}\n" +
		"                    {{range $, $secret := $secrets}}\n" +
		"                        {{template \"secret-rows\" $secret}}\n" +
		"                    {{end}}\n" +
		"                {{else}}\n" +
		"                    <div class=\"group expander row\">\n" +
		"                        <div class=\"col\">\n" +
		"                            <a href=\"javascript:\" class=\"float-left expander-link material-icons\"></a>\n" +
		"                            {{$groupName}}\n" +
		"                            ({{ len $secrets }} secrets)\n" +
		"                        </div>\n" +
		"                    </div>\n" +
		"\n" +
		"                    <div class=\"expander-target expander-collapsed\">\n" +
		"                        {{range $, $secret := $secrets}}\n" +
		"                            {{template \"secret-rows\" $secret}}\n" +
		"                        {{end}}\n" +
		"                    </div>\n" +
		"                {{end}}\n" +
		"            {{end}}\n" +
		"        </div>\n" +
		"    {{end}}\n" +
		"</div>\n" +
		"\n" +
		"<p class=\"footer\">Report generated by {{template \"link\" .AppLink}}</p>\n" +
		"\n" +
		"<script src=\"https://code.jquery.com/jquery-3.4.1.slim.min.js\"\n" +
		"        integrity=\"sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n\"\n" +
		"        crossorigin=\"anonymous\"></script>\n" +
		"<script src=\"https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js\"\n" +
		"        integrity=\"sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo\"\n" +
		"        crossorigin=\"anonymous\"></script>\n" +
		"<script src=\"https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js\"\n" +
		"        integrity=\"sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6\"\n" +
		"        crossorigin=\"anonymous\"></script>\n" +
		"{{template \"script\"}}\n" +
		"</body>\n" +
		"</html>\n" +
		"\n" +
		"{{define \"secret-rows\"}}\n" +
		"    {{- /*gotype: github.com/afbase/secrets-searcher/pkg/reporter.secretData*/ -}}\n" +
		"    <div class=\"secret expander row\">\n" +
		"        <div class=\"col col-5 label\">\n" +
		"            <a href=\"javascript:\" class=\"float-left expander-link material-icons\"></a>\n" +
		"            Secret {{.ID}}\n" +
		"        </div>\n" +
		"        <div class=\"col col-7\">\n" +
		"            <pre><code>{{ .Finding.BeforeCode }}<span\n" +
		"                            class=\"code\">{{ .Finding.CodeNoBreaks }}</span>{{ .Finding.AfterCode }}</code></pre>\n" +
		"        </div>\n" +
		"    </div>\n" +
		"    <div class=\"expander-target expander-collapsed\">\n" +
		"        <div class=\"row\">\n" +
		"            <div class=\"col col-2 label\">Secret value</div>\n" +
		"            <div class=\"col col-10\">\n" +
		"                <pre><code>{{.Value}}</code></pre>\n" +
		"            </div>\n" +
		"        </div>\n" +
		"        {{range $, $extra := .Extras}}\n" +
		"            {{template \"extra-row\" $extra}}\n" +
		"        {{end}}\n" +
		"        {{range $, $finding := .Findings}}\n" +
		"            <div class=\"finding expander row\">\n" +
		"                <div class=\"col col-2 label\">\n" +
		"                    <a href=\"javascript:\" class=\"float-left expander-link material-icons\"></a>\n" +
		"                    Finding\n" +
		"                </div>\n" +
		"                <div class=\"col col-10\">\n" +
		"                    {{$finding.CommitDate.Format \"01/02/2006\"}} /\n" +
		"                    {{template \"link\" $finding.RepoFullLink}} /\n" +
		"                    {{template \"link\" $finding.FileLineLink}}\n" +
		"                </div>\n" +
		"            </div>\n" +
		"            <div class=\"expander-target expander-collapsed\">\n" +
		"                <div class=\"row\">\n" +
		"                    <div class=\"col col-2 label\">Processor</div>\n" +
		"                    <div class=\"col col-10\">{{$finding.ProcessorName}}</div>\n" +
		"                </div>\n" +
		"                <div class=\"row\">\n" +
		"                    <div class=\"col col-2 label\">Repo</div>\n" +
		"                    <div class=\"col col-10\">{{template \"link\" $finding.RepoFullLink}}</div>\n" +
		"                </div>\n" +
		"                <div class=\"row\">\n" +
		"                    <div class=\"col col-2 label\">Commit</div>\n" +
		"                    <div class=\"col col-10\">{{template \"link\" $finding.CommitHashLink}}</div>\n" +
		"                </div>\n" +
		"                <div class=\"row\">\n" +
		"                    <div class=\"col col-2 label\">Date</div>\n" +
		"                    <div class=\"col col-10\">{{$finding.CommitDate.Format \"01/02/2006 15:04:05\"}}</div>\n" +
		"                </div>\n" +
		"                <div class=\"row\">\n" +
		"                    <div class=\"col col-2 label\">File</div>\n" +
		"                    <div class=\"col col-10\">{{template \"link\" $finding.FileLineLink}}</div>\n" +
		"                </div>\n" +
		"                <div class=\"row\">\n" +
		"                    <div class=\"col col-2 label\">Author</div>\n" +
		"                    <div class=\"col col-10\">{{$finding.CommitAuthorEmail}}</div>\n" +
		"                </div>\n" +
		"                <div class=\"row\">\n" +
		"                    <div class=\"col col-2 label\">Code</div>\n" +
		"                    <div class=\"col col-10\">\n" +
		"                                            <pre><code>{{ $finding.BeforeCode }}<span\n" +
		"                                                            class=\"code\">{{ $finding.Code }}</span>{{ $finding.AfterCode }}</code></pre>\n" +
		"                    </div>\n" +
		"                </div>\n" +
		"                {{range $, $extra := $finding.Extras}}\n" +
		"                    {{template \"extra-row\" $extra}}\n" +
		"                {{end}}\n" +
		"            </div>\n" +
		"        {{end}}\n" +
		"    </div>\n" +
		"{{end}}\n" +
		"\n" +
		"{{define \"link\"}}\n" +
		"    {{- /*gotype: github.com/afbase/secrets-searcher/pkg/reporter.linkData*/ -}}\n" +
		"    <a href=\"{{.URL}}\" title=\"{{.Tooltip}}\" data-toggle=\"tooltip\" data-placement=\"top\">{{.Label}}</a>\n" +
		"{{end}}\n" +
		"\n" +
		"{{define \"extra-row\"}}\n" +
		"    {{- /*gotype: github.com/afbase/secrets-searcher/pkg/reporter.extraData*/ -}}\n" +
		"    <div class=\"row{{if .Debug}} debug{{end}}\">\n" +
		"        <div class=\"col col-2 label\">{{.Header}}</div>\n" +
		"        <div class=\"col col-10\">{{template \"extra\" .}}</div>\n" +
		"    </div>\n" +
		"{{end}}\n" +
		"\n" +
		"{{define \"extra\"}}\n" +
		"    {{- /*gotype: github.com/afbase/secrets-searcher/pkg/reporter.extraData*/ -}}\n" +
		"    {{if .Link}}\n" +
		"        {{template \"link\" .Link}}\n" +
		"    {{else if .Code}}\n" +
		"        <pre><code>{{.Value}}</code></pre>\n" +
		"    {{else}}\n" +
		"        {{.Value}}\n" +
		"    {{end}}\n" +
		"{{end}}\n" +
		"\n" +
		"{{define \"script\"}}\n" +
		"    <script type=\"application/javascript\">\n" +
		"        $(function () {\n" +
		"            const collapsedClass = 'expander-collapsed';\n" +
		"\n" +
		"            $('[data-toggle=\"tooltip\"]').tooltip();\n" +
		"\n" +
		"            $('.expander').each(function () {\n" +
		"                const $expander = $(this);\n" +
		"                const $expanderLink = $expander.find('.expander-link');\n" +
		"                const $target = $expander.next('.expander-target');\n" +
		"                const $children = $target.find(\".expander\").filter(function () {\n" +
		"                    const $1 = $(this);\n" +
		"                    const parentsUntil = $1.parentsUntil($target);\n" +
		"                    return parentsUntil.length === 0;\n" +
		"                });\n" +
		"\n" +
		"                function updateIcon() {\n" +
		"                    $expanderLink[0].innerHTML = $target.hasClass(collapsedClass) ? 'add_circle' : 'remove_circle';\n" +
		"                }\n" +
		"\n" +
		"                function collapse() {\n" +
		"                    $target.addClass(collapsedClass);\n" +
		"                    updateIcon()\n" +
		"                }\n" +
		"\n" +
		"                function expand() {\n" +
		"                    $target.removeClass(collapsedClass);\n" +
		"                    updateIcon()\n" +
		"                }\n" +
		"\n" +
		"                function toggle() {\n" +
		"                    $target.toggleClass(collapsedClass);\n" +
		"                    updateIcon()\n" +
		"                }\n" +
		"\n" +
		"                function isCollapsed() {\n" +
		"                    return $target.hasClass(collapsedClass);\n" +
		"                }\n" +
		"\n" +
		"                function expandDecendants() {\n" +
		"                    $children.trigger(\"expandAll\")\n" +
		"                }\n" +
		"\n" +
		"                function collapseDecendants() {\n" +
		"                    $children.trigger(\"collapseAll\")\n" +
		"                }\n" +
		"\n" +
		"                function expandAll() {\n" +
		"                    expand()\n" +
		"                    expandDecendants()\n" +
		"                }\n" +
		"\n" +
		"                function collapseAll() {\n" +
		"                    collapse()\n" +
		"                    collapseDecendants()\n" +
		"                }\n" +
		"\n" +
		"                function toggleAll() {\n" +
		"                    toggle()\n" +
		"                    if (isCollapsed()) {\n" +
		"                        collapseDecendants()\n" +
		"                    } else {\n" +
		"                        expandDecendants()\n" +
		"                    }\n" +
		"                }\n" +
		"\n" +
		"                function toggleWithFullCollapse() {\n" +
		"                    toggle()\n" +
		"                    if (isCollapsed()) {\n" +
		"                        collapseDecendants()\n" +
		"                    } else {\n" +
		"                        expand()\n" +
		"                    }\n" +
		"                }\n" +
		"\n" +
		"                $expander.on(\"collapse\", collapse);\n" +
		"                $expander.on(\"expand\", expand);\n" +
		"                $expander.on(\"collapseAll\", collapseAll);\n" +
		"                $expander.on(\"expandAll\", expandAll);\n" +
		"\n" +
		"                $expanderLink.on(\"click\", function (evt) {\n" +
		"                    if (evt.altKey) {\n" +
		"                        toggleAll();\n" +
		"                    } else {\n" +
		"                        toggleWithFullCollapse();\n" +
		"                    }\n" +
		"                });\n" +
		"\n" +
		"                updateIcon()\n" +
		"            })\n" +
		"        });\n" +
		"\n" +
		"        $('.expand-all').on(\"click\", function () {\n" +
		"            $('.expander').trigger(\"expand\");\n" +
		"        });\n" +
		"        $('.collapse-all').on(\"click\", function () {\n" +
		"            $('.expander').trigger(\"collapse\");\n" +
		"        });\n" +
		"    </script>\n" +
		"{{end}}\n" +
		"\n" +
		"{{define \"styles\"}}\n" +
		"    <style>\n" +
		"        body {\n" +
		"            font-size: 14px;\n" +
		"        }\n" +
		"\n" +
		"        pre {\n" +
		"            margin: 0;\n" +
		"            background-color: #e9e9e9;\n" +
		"        }\n" +
		"\n" +
		"        .label {\n" +
		"            font-weight: bold;\n" +
		"        }\n" +
		"\n" +
		"        .code {\n" +
		"            text-decoration: underline dotted red;\n" +
		"        }\n" +
		"\n" +
		"        .expander-collapsed {\n" +
		"            display: none;\n" +
		"        }\n" +
		"\n" +
		"        .expander-link:hover {\n" +
		"            text-decoration: none;\n" +
		"        }\n" +
		"\n" +
		"        .expander-link {\n" +
		"            margin-right: 11px;\n" +
		"        }\n" +
		"\n" +
		"        .row {\n" +
		"            margin-bottom: 5px;\n" +
		"        }\n" +
		"\n" +
		"        .col > pre {\n" +
		"            padding: 3px 5px;\n" +
		"        }\n" +
		"\n" +
		"        .report-info {\n" +
		"            margin-bottom: 30px;\n" +
		"        }\n" +
		"\n" +
		"        .expander-target .label {\n" +
		"            padding-left: 50px;\n" +
		"        }\n" +
		"\n" +
		"        .expander-target .expander-target .label {\n" +
		"            padding-left: 85px;\n" +
		"        }\n" +
		"\n" +
		"        .expander-target .expander-target .expander-target .label {\n" +
		"            padding-left: 120px;\n" +
		"        }\n" +
		"\n" +
		"        .footer {\n" +
		"            text-align: center;\n" +
		"            font-style: italic;\n" +
		"            margin-top: 20px;\n" +
		"        }\n" +
		"    </style>\n" +
		"{{end}}\n" +
		"\n" +
		""
	return tmpl
}

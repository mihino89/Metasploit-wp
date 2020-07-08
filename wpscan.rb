require 'open3'
require 'fileutils'
require 'json'
require 'pp'
class MetasploitModule < Msf::Auxiliary include Msf::
    Auxiliary::
    Report def initialize super(
        'Name' =>
        'Metasploit WordPress Scanner (WPscan)',
        'Description' =>
        'Runs wpscan via Metasploit',
        'Author' => [
            'Harpreet Singh',
            'Himanshu Sharma'
        ]) register_options([
        OptString.new(
            'TARGET_URL', [
                true,
                'The target URL to be scanned using wpscan'
            ])
    ]) end def target_url datastore[
        'TARGET_URL'] end def find_wpscan_path Rex::
    FileUtils.find_full_path(
        "wpscan") end def run wpscan =
    find_wpscan_path
if wpscan.nil ? print_error(
        "Please install wpscan gem via: gem install wpscan"
    ) end tmp_file_name =
    Rex::Text.rand_text_alpha(10) cmd = [
        wpscan, "--url",
        target_url,
        "-o",
        "#{tmp_file_name}",
        "-f",
        "json", "--force"
    ]::IO.popen(cmd, "rb") do |fd |
        print_status(
            "Running WPscan on #{target_url}"
        ) print_line(
            "\t\t\t\t(This may take some time)\n"
        ) fd.each_line do |
            line |
            print_status(
                "Output: #{line.strip}"
            ) end end json =
            File.read(
                "/tmp/#{tmp_file_name}"
            ) obj = JSON.parse(
                json) i =
            0 print_line(
                "\n") print_status(
                "-------------------------------------"
            ) print_status(
                "Looking for some Interesting Findings"
            ) print_status(
                "-------------------------------------"
            ) obj = obj.compact
        while (i <= obj[
                'interesting_findings'
            ]
            .length)
    do
        if obj[
        'interesting_findings']
    [
        i
    ]['type'] == 'headers' && !(
        obj[
            'interesting_findings'
        ][i].nil ?
    ) obj[
        'interesting_findings']
    [i][
        'interesting_entries'
    ].each { | x | print_good(
            "Found Some Interesting Enteries via Header detection: #{x}"
        )
    }
i += 1 elsif obj['interesting_findings']
    [i]['type'] == 'robots_txt' &&
    (!obj['interesting_findings'][i]
        .nil ? ) obj[
        'interesting_findings']
    [i][
        'interesting_entries'
    ].each { | x | print_good(
            "Found Some Interesting Enteries via robots.txt: #{x}"
        )
    }
i += 1
else break end end print_line("\n") print_status(
    "--------------------------------------"
) print_status(
    "Looking for the WordPress version now"
) print_status(
    "--------------------------------------"
) if !(obj['version']
    .nil ? ) print_good(
    "Found WordPress version: " +
    obj['version'][
        'number'
    ] + " via " + obj[
        'version'][
        'found_by'
    ])
else print_error("Version not found") end print_status "#{obj['version']['vulnerabilities'].count} vulnerabilities identified:"
obj['version']['vulnerabilities'].each do
    |x | print_error(
        "\tTitle: #{x['title']}"
    ) print_line(
        "\tFixed in: #{x['fixed_in']}"
    ) print_line(
        "\tReferences:"
    ) x[
        'references'].each do
        |ref |
        if ref[0].include ?
    'cve'
print_line(
    "\t\t- https://cve.mitre.org/cgi-bin/cvename.cgi?name=#{ref[1][0]}"
) elsif ref[0].include ? 'url'
ref[1].each do |e | print_line(
            "\t\t- #{e}") end elsif ref[
            0].include ?
        'wpvulndb'
print_line(
    "\t\t- https://wpvulndb.com/vulnerabilities/#{ref[1][0]}"
)
end end print_line("\n") end print_line(
    "\n") print_status(
    "------------------------------------------"
) print_status(
    "Checking for installed themes in WordPress"
) print_status(
    "------------------------------------------"
) if !(obj[
    'main_theme'].nil ? ) print_good
    (
        "Theme found: " + "\"" +
        obj[
            'main_theme'][
            'slug'
        ] +
        "\"" + " via " + obj[
            'main_theme']
        ['found_by'] +
        " with version: " + obj[
            'main_theme'][
            'version'
        ]['number'])
else print_error("Theme not found") end print_line(
    "\n") print_status(
    "---------------------------------"
) print_status(
    "Enumerating installed plugins now"
) print_status(
    "---------------------------------"
) if !(obj['plugins'].nil ? ) obj
    ['plugins'].each do |x |
        if !x[1]['version'].nil ?
    print_good "Plugin Found: #{x[0]}"
print_status
    "\tPlugin Installed Version: #{x[1]['version']['number']}"
if x[1]['version']['number'] < x[1][
    'latest_version'
] print_warning "\tThe version is out of date, the latest version is #{x[1]['latest_version']}"
elsif x[1]['version']['number'] == x[1]
    ['latest_version'] print_status "\tLatest Version: #{x[1]['version']['number']} (up to date)"
else print_status "\tPlugin Location: #{x[1]['location']}"
end
else print_good "Plugin Found: #{x[0]}, Version: No version found"
end
if x[1]['vulnerabilities'].count > 0 print_status "#{x[1]['vulnerabilities'].count} vulnerabilities identified:"
x[1]['vulnerabilities'].each do |b |
    print_error(
        "\tTitle: #{b['title']}"
    ) print_line(
        "\tFixed in: #{b['fixed_in']}"
    ) print_line(
        "\tReferences:"
    ) b[
        'references'].each do
        |ref2 |
        if ref2[0].include ?
    'cve'
print_line(
    "\t\t- https://cve.mitre.org/cgi-bin/cvename.cgi?name=#{ref2[1][0]}"
) elsif ref2[0].include ? 'url'
ref2[1].each do |f | print_line(
            "\t\t- #{f}") end elsif ref2[
            0].include ?
        'exploitdb'
print_line(
    "\t\t- https://www.exploit-db.com/exploits/#{ref2[1][0]}/"
)
elsif ref2[0].include ? 'wpvulndb'
print_line(
    "\t\t- https://wpvulndb.com/vulnerabilities/#{ref2[1][0]}"
) end end print_line(
    "\n") end end end
else print_error "No plugin found\n"
end File.delete("/tmp/#{tmp_file_name}") if File
    .exist ? (
        "/tmp/#{tmp_file_name}"
    ) endend
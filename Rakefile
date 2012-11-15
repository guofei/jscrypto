task "default" => "test"

task "test" => ["init", "compile"] do
  puts "-- make distribution --"
end

task "init" do
  puts "-- initialize -- "
end

task "compile" do
  puts "-- compile --"
end

task "get_sdk" do
  puts "-- get sdk --"
  sh "svn checkout http://npapi-sdk.googlecode.com/svn/trunk/ npapi-sdk"
end
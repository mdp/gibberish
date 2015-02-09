require 'rubygems'
require 'bundler/setup'
require 'benchmark'
require 'gibberish'

N = 50
ITERATIONS = ENV["ITER"].to_i || 100_000
PLAINTEXT = "Doner meatball turducken pig chuck turkey cow. Beef ribs picanha leberkas filet mignon chicken sirloin kevin jerky. Turkey venison beef ribs, turducken capicola biltong pork loin meatball cupim jowl pork chop pancetta. Filet mignon t-bone flank spare ribs chuck kielbasa capicola turkey shank doner shoulder meatloaf pancetta. Pork belly t-bone pork loin hamburger brisket alcatra. Ham tail brisket sausage hamburger, filet mignon landjaeger jerky corned beef biltong pork chop ball tip. Shoulder pork loin ham hock pastrami brisket chuck flank. Doner meatball turducken pig chuck turkey cow. Beef ribs picanha leberkas filet mignon chicken sirloin kevin jerky. Turkey venison beef ribs, turducken capicola biltong pork loin meatball cupim jowl pork chop pancetta. Filet mignon t-bone flank spare ribs chuck kielbasa capicola turkey shank doner shoulder meatloaf pancetta. Pork belly t-bone pork loin hamburger brisket alcatra. Ham tail brisket sausage hamburger, filet mignon landjaeger jerky corned beef biltong pork chop ball tip. Shoulder pork loin ham hock pastrami brisket chuck flank. Doner meatball turducken pig chuck turkey cow. Beef ribs picanha leberkas filet mignon chicken sirloin kevin jerky. Turkey venison beef ribs, turducken capicola biltong pork loin meatball cupim jowl pork chop pancetta. Filet mignon t-bone flank spare ribs chuck kielbasa capicola turkey shank doner shoulder meatloaf pancetta. Pork belly t-bone pork loin hamburger brisket alcatra. Ham tail brisket sausage hamburger, filet mignon landjaeger jerky corned beef biltong pork chop ball tip. Shoulder pork loin ham hock pastrami brisket chuck flank. Doner meatball turducken pig chuck turkey cow. Beef ribs picanha leberkas filet mignon chicken sirloin kevin jerky. Turkey venison beef ribs, turducken capicola biltong pork loin meatball cupim jowl pork chop pancetta. Filet mignon t-bone flank spare ribs chuck kielbasa capicola turkey shank doner shoulder meatloaf pancetta. Pork belly t-bone pork loin hamburger brisket alcatra. Ham tail brisket sausage hamburger, filet mignon landjaeger jerky corned beef biltong pork chop ball tip. Shoulder pork loin ham hock pastrami brisket chuck flank."

puts "Benchmarking AES GCM: Encrypting 512 bytes #{N} times, at #{ITERATIONS} iterations\n"
cipher = Gibberish::AES.new("s33krit", iter: ITERATIONS)
plaintext = PLAINTEXT.slice(0,512)
time = Benchmark.realtime {
  N.times {
    cipher.encrypt(plaintext)
  }
}

puts "Avg time per encryption: #{'%.5f' % (time/N)}ms"


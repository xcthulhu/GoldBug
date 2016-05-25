name := "goldbug"

version := "1.0"

scalaVersion := "2.11.8"
crossScalaVersions := Seq("2.9.3", "2.10.6", "2.11.8")

libraryDependencies += "com.madgag.spongycastle" % "core" % "1.54.0.0"
libraryDependencies += "org.scalatest" % "scalatest_2.11" % "2.2.4" % "test"

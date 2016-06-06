package de.petendi.seccoco.argument;

/*-
 * #%L
 * Seccoco Java
 * %%
 * Copyright (C) 2016 P-ACS UG (haftungsbeschränkt)
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * #L%
 */


import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.File;


/**
 *
 */
public class ArgumentParser {


    private String directory;
    private String[] cmdLineArguments;
    private ArgumentList argumentList = null;

    public ArgumentParser(String directory, String[] cmdLineArguments) {
        this.directory = directory;
        this.cmdLineArguments = cmdLineArguments;
    }

    @SuppressWarnings("static-access")
    private static Options buildCommandLineOptions() {
        Options options = new Options();
        options.addOption(OptionBuilder.withLongOpt("workingdirectory").withValueSeparator('=').hasArg().create("wd"));
        options.addOption(OptionBuilder.withLongOpt("password").withValueSeparator('=').hasArg().create("pw"));
        options.addOption(OptionBuilder.withLongOpt("tokenfile").withValueSeparator('=').hasArg().create("token"));
        options.addOption(OptionBuilder.withLongOpt("help").withValueSeparator('=').create("h"));

        return options;

    }

    private static void showHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(" ", buildCommandLineOptions());

    }

    public synchronized ArgumentList getArgumentList() {
        if (argumentList == null) {
            parse();
        }
        return argumentList;
    }

    private void parse() {
        boolean showHelp = false;
        argumentList = new ArgumentList();

        CommandLineParser parser = new BasicParser();
        try {
            CommandLine commandLine = parser.parse(buildCommandLineOptions(), cmdLineArguments);
            String workingDirectoryArg = commandLine.getOptionValue("wd", null);
            if (workingDirectoryArg != null) {
                File workingDirectory = new File(workingDirectoryArg);
                if (!workingDirectory.isDirectory()) {
                    throw new ArgumentParseException("not a directory " + workingDirectoryArg);
                } else {
                    argumentList.setWorkingDirectory(workingDirectory);
                }
            }
            String tokenFile = commandLine.getOptionValue("token", null);
            if (tokenFile != null) {
                File token = new File(tokenFile);
                if (!token.isAbsolute()) {
                    if (argumentList.getWorkingDirectory() == null) {
                        throw new ArgumentParseException("relative token needs working directory: " + token);
                    } else {
                        token = new File(argumentList.getWorkingDirectory(), tokenFile);
                    }
                }
                if (!token.exists()) {
                    throw new ArgumentParseException("token not found: " + token);
                }
                if (!token.canRead()) {
                    throw new ArgumentParseException("token not readable:" + token);
                }

                argumentList.setToken(token);

            }

            String password = commandLine.getOptionValue("pw", "");
            argumentList.setTokenPassword(password.toCharArray());

            argumentList.setUserDirectory(directory);
            showHelp = commandLine.hasOption("h");


        } catch (ParseException e) {
            showHelp();
            throw new ArgumentParseException(e.toString());

        }

        if (showHelp) {
            showHelp();
            throw new HelpTextRequestedException();
        }


    }

}

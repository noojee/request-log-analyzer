module RequestLogAnalyzer::FileFormat

  # Default FileFormat class for Rails 3 logs.
  #
  # For now, this is just a basic implementation. It will probaby change after
  # Rails 3 final has been released.
  class OinkRails3 < Rails3

    extend CommonRegularExpressions

    # beta4: Started GET "/" for 127.0.0.1 at Wed Jul 07 09:13:27 -0700 2010 (different time format)
    line_definition :started do |line|
      line.header = true
      line.teaser = /\[(\d+)\]: Started /
      line.regexp = /\[(\d+)\]: Started ([A-Z]+) "([^"]+)" for (#{ip_address}) at (#{timestamp('%a %b %d %H:%M:%S %z %Y')}|#{timestamp('%Y-%m-%d %H:%M:%S %z')})/
      
      line.capture(:pid).as(:integer)
      line.capture(:method)
      line.capture(:path)
      line.capture(:ip)
      line.capture(:timestamp).as(:timestamp)
    end
    
    # Processing by QueriesController#index as HTML
    line_definition :processing do |line|
      line.teaser = /\[(\d+)\]: Processing by /
      line.regexp = /\[(\d+)\]: Processing by ([A-Za-z0-9\-:]+)\#(\w+) as ([\w\/\*]*)/
      
      line.capture(:pid).as(:integer)
      line.capture(:controller)
      line.capture(:action)
      line.capture(:format)
    end

    # Parameters: {"action"=>"cached", "controller"=>"cached"}
    line_definition :parameters do |line|
      line.teaser = /\[(\d+)\]:  Parameters:/
      line.regexp = /\[(\d+)\]: Parameters:\s+(\{.*\})/
      line.capture(:pid).as(:integer)
      line.capture(:params).as(:eval)
    end
    
    # Completed 200 OK in 224ms (Views: 200.2ms | ActiveRecord: 3.4ms)
    # Completed 302 Found in 23ms
    # Completed in 189ms
    line_definition :completed do |line|
      line.footer = true
      line.teaser = /\[(\d+)\]: Completed /
      line.regexp = /\[(\d+)\]: Completed (\d+)? .*in (\d+(?:\.\d+)?)ms(?:[^\(]*\(Views: (\d+(?:\.\d+)?)ms .* ActiveRecord: (\d+(?:\.\d+)?)ms.*\))?/
      
      line.capture(:pid).as(:integer)
      line.capture(:status).as(:integer)
      line.capture(:duration).as(:duration, :unit => :msec)
      line.capture(:view).as(:duration, :unit => :msec)
      line.capture(:db).as(:duration, :unit => :msec)
    end

    line_definition :memory_usage do |line|
      line.regexp   = /\[(\d+)\]: Memory usage: (\d+)/
      line.capture(:pid).as(:integer)
      line.capture(:memory).as(:traffic)
    end

    line_definition :instance_type_counter do |line|
      line.regexp = /\[(\d+)\]: Instantiation Breakdown: (.*)$/
      line.capture(:pid).as(:integer)
      line.capture(:instance_counts).as(:pipe_separated_counts)
    end

    # ActionView::Template::Error (undefined local variable or method `field' for #<Class>) on line #3 of /Users/willem/Code/warehouse/app/views/queries/execute.csv.erb:
    line_definition :failure do |line|
      line.footer = true
      line.regexp = /\[(\d+)\]: ((?:[A-Z]\w*[a-z]\w+\:\:)*[A-Z]\w*[a-z]\w+) \((.*)\)(?: on line #(\d+) of (.+))?\:\s*$/

      line.capture(:pid)
      line.capture(:error)
      line.capture(:message)
      line.capture(:line).as(:integer)
      line.capture(:file)
    end

    report(:append) do |analyze|
      analyze.traffic :memory_diff, :category => REQUEST_CATEGORIZER, :title => "Largest Memory Increases", :line_type => :memory_usage
    end
    
    # Keep a record of PIDs and their memory usage when validating requests.
    def pids
      @pids ||= {}
    end

    class Request < RequestLogAnalyzer::FileFormat::Rails::Request
      # Overrides the #validate method to handle PID updating.
      def validate
        update_pids
        super
      end
     
      # Accessor for memory information associated with the specified request PID. If no memory exists
      # for this request's :pid, the memory tracking is initialized.
      def pid_memory
        file_format.pids[self[:pid]] ||= { :last_memory_reading => -1, :current_memory_reading => -1 }
      end
      
      # Calculates :memory_diff for each request based on the last completed request that was not a failure.
      def update_pids
        # memory isn't recorded with exceptions. need to set #last_memory_reading+ to -1 as
        # the memory used could have changed. for the next request the memory change will not be recorded.
        #
        # NOTE - the failure regex was not matching with a Rails Development log file.
        if has_line_type?(:failure) and processing = has_line_type?(:processing)
          pid_memory[:last_memory_reading] = -1
        elsif mem_line = has_line_type?(:memory_usage)
          memory_reading = mem_line[:memory]
          pid_memory[:current_memory_reading] = memory_reading
          # calcuate the change in memory
          unless pid_memory[:current_memory_reading] == -1 || pid_memory[:last_memory_reading] == -1
            # logged as kB, need to convert to bytes for the :traffic Tracker
            memory_diff = (pid_memory[:current_memory_reading] - pid_memory[:last_memory_reading])*1024
            if memory_diff > 0
              self.attributes[:memory_diff] = memory_diff
            end # if memory_diff > 0
          end # unless
          
          pid_memory[:last_memory_reading] = pid_memory[:current_memory_reading]
          pid_memory[:current_memory_reading] = -1
        end # if mem_line
        return true
      end # def update_pids

      def convert_pipe_separated_counts(value, capture_definition)
        count_strings = value.split(' | ')
        count_arrays = count_strings.map do |count_string|
          if count_string =~ /^(\w+): (\d+)/
            [$1, $2.to_i]
          end
        end

        Hash[count_arrays]
      end
    end # class Request
  end
end
